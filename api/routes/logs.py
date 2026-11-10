from fastapi import APIRouter, Query

from core.database import es_client

router = APIRouter()


@router.get("/search")
async def search_logs(
    q: str = Query(default="", max_length=500),
    anomalous_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
):
    """
    Search analysed logs in Elasticsearch (newest first). An empty ``q`` lists the
    most recent entries. ``source`` is "unavailable" when Elasticsearch is disabled or
    unreachable, so the dashboard can say so instead of showing an empty result.
    """
    logs = await es_client.search_logs(q.strip() or None, limit=limit, anomalous_only=anomalous_only)
    if logs is None:
        return {"logs": [], "count": 0, "source": "unavailable"}
    return {"logs": logs, "count": len(logs), "source": "elasticsearch"}
