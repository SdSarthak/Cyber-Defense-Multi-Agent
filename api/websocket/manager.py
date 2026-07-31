"""WebSocket connection manager + Redis pub/sub bridge for real-time dashboard updates."""
import asyncio
import json

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from core import metrics
from core.config import settings
from core.database import redis_client

log = structlog.get_logger()

ws_router = APIRouter()

CHANNELS = ["agent_events", "escalations", "incident_updates"]

# Commands a dashboard operator may issue over the socket.
OVERRIDE_COMMANDS = ("pause_agent", "resume_agent", "set_threat_level", "run_agent")

# Overrides that mutate agent state are admin-only; everyone else gets read-only telemetry.
ADMIN_ONLY_COMMANDS = ("pause_agent", "resume_agent", "run_agent")

# RFC 6455 close codes. 1008 = policy violation, which is what browsers surface for
# an auth failure during the handshake.
WS_POLICY_VIOLATION = 1008


def _extract_ws_token(ws: WebSocket) -> str:
    """
    Pull a bearer token off the handshake.

    Browsers cannot set headers on a WebSocket handshake, so `?token=` is the
    portable option; the Authorization header is still honoured for CLI clients.
    """
    token = ws.query_params.get("token", "")
    if token:
        return token.strip()
    header = ws.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def authenticate_websocket(ws: WebSocket) -> dict | None:
    """
    Return the JWT claims for a socket, or None when the handshake is not authorised.

    When `websocket_auth_required` is off the socket is treated as an anonymous
    analyst — useful for local demos, never for a deployment reachable off-host.
    """
    token = _extract_ws_token(ws)
    if not token:
        if settings.websocket_auth_required:
            return None
        return {"sub": "anonymous", "role": "analyst"}
    try:
        return jwt.decode(token, settings.api_secret_key, algorithms=[settings.api_algorithm])
    except JWTError:
        return None


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    @property
    def count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        metrics.websocket_connections_active.set(len(self._connections))

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)
        metrics.websocket_connections_active.set(len(self._connections))

    async def broadcast(self, message: dict):
        dead = []
        for ws in list(self._connections):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


async def _subscribe(channels: list[str]):
    """
    Yield decoded pub/sub messages, reconnecting on failure.

    Without the retry loop a single Redis blip permanently kills the dashboard feed
    for the lifetime of the process.
    """
    while True:
        pubsub = None
        try:
            pubsub = redis_client.get_redis().pubsub()
            await pubsub.subscribe(*channels)
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    data = json.loads(message["data"])
                except (json.JSONDecodeError, TypeError):
                    data = {"raw": message["data"]}
                yield message["channel"], data
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("pubsub.reconnecting", channels=channels, error=str(exc))
            await asyncio.sleep(2.0)
        finally:
            if pubsub is not None:
                try:
                    await pubsub.aclose()
                except Exception:
                    pass


async def redis_listener():
    """Background task: subscribe to Redis channels and broadcast to WebSocket clients."""
    async for channel, data in _subscribe(CHANNELS):
        await manager.broadcast({"channel": channel, "data": data})


async def escalation_listener(supervisor):
    """
    Background task: forward escalations to the Supervisor so it can open an incident.

    Previously `SupervisorAgent.handle_escalation` existed but nothing ever called it,
    so a critical escalation reached the dashboard and stopped there.
    """
    if not settings.escalation_auto_response:
        return
    async for _, escalation in _subscribe(["escalations"]):
        try:
            await supervisor.handle_escalation(escalation)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("escalation_listener.failed", error=str(exc))


def _reject_unknown_agent(command: str, agent, supervisor) -> dict | None:
    """
    Validate ``payload.agent`` for the commands that need one.

    Without this a typo writes a pause key for an agent that does not exist: the
    command reports success, the operator believes the agent is stopped, and it keeps
    running. Returns an error payload, or None when the name is acceptable.
    """
    if not agent:
        return {"ok": False, "error": f"{command} requires payload.agent"}
    known = getattr(supervisor, "agent_names", None)
    if known and agent not in known:
        return {"ok": False, "error": f"Unknown agent: {agent}", "supported": list(known)}
    return None


async def _handle_override(command: str, payload: dict, supervisor=None) -> dict:
    """Apply a human override command. Returns a result payload for the caller."""
    from agents.base_agent import BaseSecurityAgent

    agent = payload.get("agent")

    if command == "pause_agent":
        rejection = _reject_unknown_agent(command, agent, supervisor)
        if rejection:
            return rejection
        await BaseSecurityAgent.pause(agent)
        return {"ok": True, "agent": agent, "status": "paused"}

    if command == "resume_agent":
        rejection = _reject_unknown_agent(command, agent, supervisor)
        if rejection:
            return rejection
        await BaseSecurityAgent.resume(agent)
        return {"ok": True, "agent": agent, "status": "resumed"}

    if command == "set_threat_level":
        level = str(payload.get("threat_level", "low")).lower()
        from core.memory.agent_memory import AgentMemory
        await AgentMemory.blackboard_set("threat_level", level, ttl=3600)
        metrics.set_threat_level(level)
        return {"ok": True, "threat_level": level}

    if command == "run_agent":
        if supervisor is None:
            return {"ok": False, "error": "Supervisor unavailable"}
        rejection = _reject_unknown_agent(command, agent, supervisor)
        if rejection:
            return rejection
        result = await supervisor._run_agent(agent, payload.get("task") or {})
        return {"ok": True, "agent": agent, "summary": result.get("summary", "")}

    return {"ok": False, "error": f"Unknown command: {command}"}


@ws_router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    claims = authenticate_websocket(ws)
    if claims is None:
        # Close before accepting: the client never sees a half-open authorised socket.
        await ws.close(code=WS_POLICY_VIOLATION, reason="Missing or invalid token")
        return

    role = claims.get("role", "analyst")
    await manager.connect(ws)
    await ws.send_json({
        "type": "connected",
        "user": claims.get("sub"),
        "role": role,
        "channels": CHANNELS,
    })
    try:
        while True:
            # Accept any incoming messages (human override commands)
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({"type": "error", "error": "Malformed JSON"})
                continue

            if msg.get("type") != "human_override":
                continue

            command = str(msg.get("command", ""))
            payload = msg.get("payload") or {}
            if command not in OVERRIDE_COMMANDS:
                await ws.send_json({
                    "type": "override_result",
                    "command": command,
                    "result": {"ok": False, "error": f"Unsupported command: {command}",
                               "supported": list(OVERRIDE_COMMANDS)},
                })
                continue

            if command in ADMIN_ONLY_COMMANDS and role != "admin":
                await ws.send_json({
                    "type": "override_result",
                    "command": command,
                    "result": {"ok": False, "error": f"Role '{role}' may not run {command}"},
                })
                continue

            try:
                supervisor = getattr(ws.app.state, "supervisor", None)
                result = await _handle_override(command, payload, supervisor)
            except Exception as exc:
                log.warning("override.failed", command=command, error=str(exc))
                result = {"ok": False, "error": str(exc)}

            await ws.send_json({"type": "override_result", "command": command, "result": result})

            try:
                await redis_client.cache.publish("agent_events", {
                    "agent": "human",
                    "event": "override",
                    "user": claims.get("sub"),
                    "command": command,
                    "payload": payload,
                    "result": result,
                })
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.warning("websocket.error", error=str(exc))
    finally:
        # In a `finally`, not per-handler: a cancelled task (server shutdown, client
        # reset) raises BaseException, which skipped both handlers and left the socket
        # registered forever — leaking the object and pinning
        # `websocket_connections_active` above the real connection count.
        manager.disconnect(ws)
