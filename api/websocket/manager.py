"""WebSocket connection manager + Redis pub/sub bridge for real-time dashboard updates."""
import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from core.database.redis_client import get_redis

ws_router = APIRouter()

CHANNELS = ["agent_events", "escalations", "incident_updates"]


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self._connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


async def redis_listener():
    """Background task: subscribe to Redis channels and broadcast to WebSocket clients."""
    redis = get_redis()
    pubsub = redis.pubsub()
    await pubsub.subscribe(*CHANNELS)
    async for message in pubsub.listen():
        if message["type"] == "message":
            try:
                data = json.loads(message["data"])
                await manager.broadcast({
                    "channel": message["channel"],
                    "data": data,
                })
            except Exception:
                pass


@ws_router.on_event("startup")
async def start_redis_listener():
    asyncio.create_task(redis_listener())


@ws_router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Accept any incoming messages (human override commands)
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
                if msg.get("type") == "human_override":
                    from core.database.redis_client import cache
                    await cache.publish("agent_events", {
                        "agent": "human",
                        "event": "override",
                        "command": msg.get("command"),
                        "payload": msg.get("payload"),
                    })
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(ws)
