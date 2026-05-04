"""
Two-tier memory for each agent:
  - Short-term: Redis (TTL-backed, task-scoped)
  - Long-term:  PostgreSQL via AgentAction audit log + Redis sorted sets for recency
"""
from __future__ import annotations
import json
from datetime import datetime
from core.database.redis_client import cache


class AgentMemory:
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self._prefix = f"agent:{agent_name}"

    # ── Short-term (Redis) ────────────────────────────────────────────────────

    async def remember(self, key: str, value, ttl: int = 1800) -> None:
        await cache.set(f"{self._prefix}:st:{key}", value, ttl=ttl)

    async def recall(self, key: str):
        return await cache.get(f"{self._prefix}:st:{key}")

    async def forget(self, key: str) -> None:
        await cache.delete(f"{self._prefix}:st:{key}")

    async def set_task_context(self, task_id: str, context: dict) -> None:
        await cache.set(f"{self._prefix}:task:{task_id}", context, ttl=7200)

    async def get_task_context(self, task_id: str) -> dict | None:
        return await cache.get(f"{self._prefix}:task:{task_id}")

    # ── Working memory (in-process dict, cleared per task) ───────────────────

    def new_working_memory(self) -> dict:
        return {
            "agent": self.agent_name,
            "started_at": datetime.utcnow().isoformat(),
            "observations": [],
            "decisions": [],
            "tool_calls": [],
        }

    # ── Long-term event log (Redis list, capped at 200) ───────────────────────

    async def log_event(self, event: dict) -> None:
        key = f"{self._prefix}:history"
        event["ts"] = datetime.utcnow().isoformat()
        await cache.lpush(key, event)
        # keep only last 200
        redis = cache._redis
        await redis.ltrim(key, 0, 199)

    async def get_history(self, limit: int = 20) -> list[dict]:
        return await cache.lrange(f"{self._prefix}:history", 0, limit - 1)

    # ── Shared blackboard (all agents read/write) ─────────────────────────────

    @staticmethod
    async def blackboard_set(key: str, value, ttl: int = 3600) -> None:
        await cache.set(f"blackboard:{key}", value, ttl=ttl)

    @staticmethod
    async def blackboard_get(key: str):
        return await cache.get(f"blackboard:{key}")

    @staticmethod
    async def blackboard_update(key: str, update: dict, ttl: int = 3600) -> None:
        existing = await AgentMemory.blackboard_get(key) or {}
        existing.update(update)
        await AgentMemory.blackboard_set(key, existing, ttl=ttl)
