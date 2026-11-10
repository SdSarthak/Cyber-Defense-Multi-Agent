import json
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from core.config import settings

_pool: aioredis.ConnectionPool | None = None
_blocking_pool: aioredis.ConnectionPool | None = None


def get_redis_pool() -> aioredis.ConnectionPool:
    """Pool for ordinary commands — bounded so a hung Redis cannot hang every request."""
    global _pool
    if _pool is None:
        _pool = aioredis.ConnectionPool.from_url(
            settings.redis_url,
            max_connections=50,
            decode_responses=True,
            socket_timeout=settings.redis_socket_timeout,
            socket_connect_timeout=settings.redis_socket_timeout,
        )
    return _pool


def get_blocking_pool() -> aioredis.ConnectionPool:
    """
    Pool for long-lived blocking readers (pub/sub, XREADGROUP BLOCK).

    A read timeout on these connections would fire whenever the channel is simply
    quiet, so they only bound the connect phase.
    """
    global _blocking_pool
    if _blocking_pool is None:
        _blocking_pool = aioredis.ConnectionPool.from_url(
            settings.redis_url,
            max_connections=10,
            decode_responses=True,
            socket_connect_timeout=settings.redis_socket_timeout,
            health_check_interval=30,
        )
    return _blocking_pool


def get_redis() -> aioredis.Redis:
    return aioredis.Redis(connection_pool=get_redis_pool())


def get_blocking_redis() -> aioredis.Redis:
    return aioredis.Redis(connection_pool=get_blocking_pool())


async def close_pools() -> None:
    global _pool, _blocking_pool
    for pool in (_pool, _blocking_pool):
        if pool is not None:
            try:
                await pool.disconnect()
            except Exception:
                pass
    _pool = None
    _blocking_pool = None


def _loads(raw: Any) -> Any:
    """Tolerate values written to Redis by other producers as plain strings."""
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


def _decode_entries(entries) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for entry_id, fields in entries or []:
        if fields is None:  # deleted while pending
            continue
        out.append((entry_id, _loads(fields.get("data"))))
    return out


class RedisCache:
    """Typed Redis wrapper used by agents for short-term task memory."""

    def __init__(self):
        self._redis = get_redis()

    async def set(self, key: str, value: Any, ttl: int | None = 3600) -> None:
        """Store JSON. ``ttl=None`` keeps the key until it is deleted."""
        payload = json.dumps(value, default=str)
        if ttl is None:
            await self._redis.set(key, payload)
        else:
            await self._redis.setex(key, ttl, payload)

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

    async def incr_window(self, key: str, ttl: int) -> int:
        """INCR a counter that expires ``ttl`` seconds after its first increment."""
        value = int(await self._redis.incr(key))
        if value == 1:
            await self._redis.expire(key, ttl)
        return value

    async def set_if_absent(self, key: str, value: Any, ttl: int) -> bool:
        """SET NX EX — returns True when the caller won the race (used for cooldowns)."""
        return bool(await self._redis.set(key, json.dumps(value, default=str), ex=ttl, nx=True))

    async def hset(self, name: str, mapping: dict) -> None:
        await self._redis.hset(name, mapping={k: json.dumps(v, default=str) for k, v in mapping.items()})

    async def hgetall(self, name: str) -> dict:
        raw = await self._redis.hgetall(name)
        return {k: _loads(v) for k, v in raw.items()}

    # ── Streams (durable work queues) ────────────────────────────────────────

    async def xadd(self, stream: str, value: Any, maxlen: int = 10_000) -> str:
        return await self._redis.xadd(
            stream, {"data": json.dumps(value, default=str)}, maxlen=maxlen, approximate=True
        )

    async def ensure_group(self, stream: str, group: str) -> None:
        try:
            await self._redis.xgroup_create(stream, group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def xreadgroup(
        self, stream: str, group: str, consumer: str, count: int = 10, block_ms: int = 5000
    ) -> list[tuple[str, Any]]:
        # Blocking read: use the pool without a read timeout.
        response = await get_blocking_redis().xreadgroup(
            group, consumer, {stream: ">"}, count=count, block=block_ms
        )
        entries: list = []
        for _stream, items in response or []:
            entries.extend(items)
        return _decode_entries(entries)

    async def xautoclaim(
        self, stream: str, group: str, consumer: str, min_idle_ms: int, count: int = 10
    ) -> list[tuple[str, Any]]:
        """Take over entries another consumer read but never acknowledged (it crashed)."""
        response = await self._redis.xautoclaim(
            stream, group, consumer, min_idle_time=min_idle_ms, start_id="0-0", count=count
        )
        claimed = response[1] if isinstance(response, (list, tuple)) and len(response) > 1 else []
        return _decode_entries(claimed)

    async def xack(self, stream: str, group: str, *ids: str) -> None:
        if ids:
            await self._redis.xack(stream, group, *ids)


cache = RedisCache()
