import asyncio

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from core.config import settings
from core.database import es_client, redis_client
from core.database.base import engine

router = APIRouter()


async def _check_redis() -> bool:
    try:
        return bool(await redis_client.get_redis().ping())
    except Exception:
        return False


async def _check_postgres() -> bool:
    if not settings.enable_persistence:
        return False
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def _check_elasticsearch() -> bool:
    try:
        return await es_client.ping()
    except Exception:
        return False


async def _check_chroma() -> bool:
    from core.rag.vector_store import vector_store
    try:
        return await asyncio.to_thread(vector_store.is_available)
    except Exception:
        return False


@router.get("/health")
async def health():
    """Liveness probe — always 200 so the container is not killed when a backing service blips."""
    return {"status": "ok", "redis": await _check_redis()}


@router.get("/health/ready")
async def readiness(response: Response):
    """
    Readiness probe — reports every backing service and returns 503 when a
    dependency the platform cannot work without (Redis) is down.
    """
    checks = dict(zip(
        ("redis", "postgres", "elasticsearch", "chromadb"),
        await asyncio.gather(
            _check_redis(), _check_postgres(), _check_elasticsearch(), _check_chroma(),
        ),
    ))
    ready = checks["redis"]
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready else "degraded",
        "checks": checks,
        # These are optional: the mesh degrades gracefully without them.
        "optional": ["postgres", "elasticsearch", "chromadb"],
    }
