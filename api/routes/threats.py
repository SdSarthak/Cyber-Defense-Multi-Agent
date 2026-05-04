from fastapi import APIRouter, Request, Query
from pydantic import BaseModel
from typing import Any

router = APIRouter()


class ThreatEventRequest(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    message: str = ""
    raw: str = ""
    metadata: dict[str, Any] = {}


@router.post("/analyze")
async def analyze_threat(request: Request, body: ThreatEventRequest):
    supervisor = request.app.state.supervisor
    result = await supervisor._run_agent("threat_detection", body.model_dump())
    return result


@router.post("/batch-analyze")
async def batch_analyze(request: Request, events: list[ThreatEventRequest]):
    supervisor = request.app.state.supervisor
    results = []
    for event in events[:20]:
        r = await supervisor._run_agent("threat_detection", event.model_dump())
        results.append(r)
    return {"results": results, "count": len(results)}


@router.get("/recent")
async def get_recent_threats(limit: int = Query(default=50, le=200)):
    from core.database.redis_client import cache
    history = await cache.lrange("agent:threat_detection:history", 0, limit - 1)
    return {"threats": history, "count": len(history)}
