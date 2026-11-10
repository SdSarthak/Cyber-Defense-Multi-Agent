"""
Agent memory backed by Redis:
  - a capped per-agent event history (the durable audit trail is the PostgreSQL
    AgentAction table, written by BaseSecurityAgent);
  - the shared blackboard all agents read and write.

The module accesses ``redis_client.cache`` through the module object rather than
importing the singleton by value, so a single patch point swaps the backing store
for the whole process (used by the test-suite's in-memory fake).
"""
from __future__ import annotations

from datetime import datetime, timezone

import structlog

from core.database import redis_client

log = structlog.get_logger()

HISTORY_LIMIT = 200


class AgentMemory:
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self._prefix = f"agent:{agent_name}"

    # ── Long-term event log (Redis list, capped) ──────────────────────────────

    async def log_event(self, event: dict) -> None:
        """Append to the agent's rolling history. Never raises — telemetry is not critical path."""
        key = f"{self._prefix}:history"
        event = {**event, "ts": datetime.now(timezone.utc).isoformat()}
        try:
            await redis_client.cache.lpush(key, event)
            await redis_client.cache.ltrim(key, 0, HISTORY_LIMIT - 1)
        except Exception as exc:
            log.warning("memory.log_event_failed", agent=self.agent_name, error=str(exc))

    async def get_history(self, limit: int = 20) -> list[dict]:
        try:
            return await redis_client.cache.lrange(f"{self._prefix}:history", 0, limit - 1)
        except Exception as exc:
            log.warning("memory.get_history_failed", agent=self.agent_name, error=str(exc))
            return []

    # ── Shared blackboard (all agents read/write) ─────────────────────────────

    @staticmethod
    async def blackboard_set(key: str, value, ttl: int = 3600) -> None:
        await redis_client.cache.set(f"blackboard:{key}", value, ttl=ttl)

    @staticmethod
    async def blackboard_get(key: str):
        return await redis_client.cache.get(f"blackboard:{key}")

    @staticmethod
    async def blackboard_update(key: str, update: dict, ttl: int = 3600) -> None:
        existing = await AgentMemory.blackboard_get(key)
        if not isinstance(existing, dict):
            existing = {}
        existing.update(update)
        await AgentMemory.blackboard_set(key, existing, ttl=ttl)
