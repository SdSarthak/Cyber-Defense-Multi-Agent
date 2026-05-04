"""
Redis pub/sub event bus for inter-agent communication.
Channels:
  - cyberdefense:threats      → new threat events
  - cyberdefense:incidents    → incident state changes
  - cyberdefense:alerts       → high-priority alerts (fan-out to dashboard)
  - cyberdefense:agent:cmd    → supervisor commands to agents
  - cyberdefense:agent:status → agent heartbeats / status updates
"""
from __future__ import annotations
import asyncio
import json
from typing import Callable, Awaitable
from core.database.redis_client import get_redis

CHANNEL_THREATS = "cyberdefense:threats"
CHANNEL_INCIDENTS = "cyberdefense:incidents"
CHANNEL_ALERTS = "cyberdefense:alerts"
CHANNEL_CMD = "cyberdefense:agent:cmd"
CHANNEL_STATUS = "cyberdefense:agent:status"


class EventBus:
    async def publish(self, channel: str, payload: dict) -> None:
        redis = get_redis()
        await redis.publish(channel, json.dumps(payload, default=str))

    async def subscribe(
        self,
        channels: list[str],
        handler: Callable[[str, dict], Awaitable[None]],
    ) -> None:
        redis = get_redis()
        pubsub = redis.pubsub()
        await pubsub.subscribe(*channels)
        async for message in pubsub.listen():
            if message["type"] == "message":
                channel = message["channel"]
                try:
                    data = json.loads(message["data"])
                except (json.JSONDecodeError, TypeError):
                    data = {"raw": message["data"]}
                await handler(channel, data)

    # ── Convenience publishers ─────────────────────────────────────────────────

    async def emit_threat(self, threat: dict) -> None:
        await self.publish(CHANNEL_THREATS, {"event": "new_threat", **threat})

    async def emit_incident(self, incident_id: str, status: str, data: dict) -> None:
        await self.publish(CHANNEL_INCIDENTS, {
            "event": "incident_update",
            "incident_id": incident_id,
            "status": status,
            **data,
        })

    async def emit_alert(self, severity: str, message: str, data: dict) -> None:
        await self.publish(CHANNEL_ALERTS, {
            "event": "alert",
            "severity": severity,
            "message": message,
            **data,
        })

    async def send_command(self, target_agent: str, command: str, payload: dict) -> None:
        await self.publish(CHANNEL_CMD, {
            "target": target_agent,
            "command": command,
            **payload,
        })

    async def heartbeat(self, agent_name: str, status: str, task: str | None = None) -> None:
        await self.publish(CHANNEL_STATUS, {
            "agent": agent_name,
            "status": status,
            "current_task": task,
        })


event_bus = EventBus()
