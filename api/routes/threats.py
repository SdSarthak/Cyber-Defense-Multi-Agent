from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.database import repository

router = APIRouter()

MAX_BATCH_EVENTS = 20


class ThreatEventRequest(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    message: str = ""
    raw: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


def _get_supervisor(request: Request):
    supervisor = getattr(request.app.state, "supervisor", None)
    if supervisor is None:
        raise HTTPException(status_code=503, detail="Agent mesh is not initialised")
    return supervisor


@router.post("/analyze")
async def analyze_threat(request: Request, body: ThreatEventRequest):
    supervisor = _get_supervisor(request)
    return await supervisor._run_agent("threat_detection", body.model_dump())


@router.post("/batch-analyze")
async def batch_analyze(request: Request, events: list[ThreatEventRequest]):
    if not events:
        raise HTTPException(status_code=400, detail="No events supplied")
    if len(events) > MAX_BATCH_EVENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Batch too large: {len(events)} events (max {MAX_BATCH_EVENTS})",
        )
    supervisor = _get_supervisor(request)
    results = []
    for event in events:
        try:
            results.append(await supervisor._run_agent("threat_detection", event.model_dump()))
        except Exception as exc:
            results.append({"error": str(exc), "summary": "Analysis failed"})
    return {"results": results, "count": len(results)}


@router.get("/recent")
async def get_recent_threats(
    limit: int = Query(default=50, ge=1, le=200),
    severity: str | None = Query(default=None),
):
    """
    Recent classified threats from PostgreSQL, falling back to the agent's Redis
    history when persistence is disabled or the database is unreachable.
    """
    threats = await repository.recent_threat_events(limit=limit, severity=severity)
    source = "postgres"
    if not threats:
        from core.database import redis_client
        try:
            threats = await redis_client.cache.lrange(
                "agent:threat_detection:history", 0, limit - 1
            )
        except Exception:
            threats = []
        source = "redis"
    return {"threats": threats, "count": len(threats), "source": source}


@router.get("/stats")
async def get_threat_stats(hours: int = Query(default=24, ge=1, le=720)):
    """Severity breakdown over the trailing window — powers the dashboard chart."""
    counts = await repository.threat_severity_counts(hours=hours)
    return {"window_hours": hours, "counts": counts, "total": sum(counts.values())}
