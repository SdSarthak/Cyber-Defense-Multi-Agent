import json
from typing import Any
import redis.asyncio as aioredis
from core.config import settings

_pool: aioredis.ConnectionPool | None = None


def get_redis_pool() -> aioredis.ConnectionPool:
    global _pool
    if _pool is None:
        _pool = aioredis.ConnectionPool.from_url(
            settings.redis_url,
            max_connections=20,
            decode_responses=True,
        )
    return _pool


def get_redis() -> aioredis.Redis:
    return aioredis.Redis(connection_pool=get_redis_pool())


def _loads(raw: Any) -> Any:
    """Tolerate values written to Redis by other producers as plain strings."""
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


class RedisCache:
    """Typed Redis wrapper used by agents for short-term task memory."""

    def __init__(self):
        self._redis = get_redis()

    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        await self._redis.setex(key, ttl, json.dumps(value, default=str))

    async def get(self, key: str) -> Any | None:
        return _loads(await self._redis.get(key))

    async def delete(self, key: str) -> None:
        await self._redis.delete(key)

    async def exists(self, key: str) -> bool:
        return bool(await self._redis.exists(key))

    async def expire(self, key: str, ttl: int) -> None:
        await self._redis.expire(key, ttl)

    async def publish(self, channel: str, message: Any) -> None:
        await self._redis.publish(channel, json.dumps(message, default=str))

    async def lpush(self, key: str, value: Any) -> None:
        await self._redis.lpush(key, json.dumps(value, default=str))

    async def rpop(self, key: str) -> Any | None:
        return _loads(await self._redis.rpop(key))

    async def lrange(self, key: str, start: int = 0, end: int = -1) -> list[Any]:
        items = await self._redis.lrange(key, start, end)
        return [_loads(i) for i in items]

    async def ltrim(self, key: str, start: int, end: int) -> None:
        await self._redis.ltrim(key, start, end)

    async def llen(self, key: str) -> int:
        return int(await self._redis.llen(key))

    async def incr(self, key: str) -> int:
        return await self._redis.incr(key)

    async def set_if_absent(self, key: str, value: Any, ttl: int) -> bool:
        """SET NX EX — returns True when the caller won the race (used for cooldowns)."""
        return bool(await self._redis.set(key, json.dumps(value, default=str), ex=ttl, nx=True))

    async def hset(self, name: str, mapping: dict) -> None:
        await self._redis.hset(name, mapping={k: json.dumps(v, default=str) for k, v in mapping.items()})

    async def hgetall(self, name: str) -> dict:
        raw = await self._redis.hgetall(name)
        return {k: _loads(v) for k, v in raw.items()}


cache = RedisCache()
