from fastapi import APIRouter
from core.database.redis_client import get_redis

router = APIRouter()


@router.get("/health")
async def health():
    redis_ok = False
    try:
        redis = get_redis()
        await redis.ping()
        redis_ok = True
    except Exception:
        pass
    return {"status": "ok", "redis": redis_ok}
