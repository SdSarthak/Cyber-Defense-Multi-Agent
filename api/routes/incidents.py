from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.database import redis_client, repository

router = APIRouter()

VALID_STATUSES = ["open", "investigating", "contained", "resolved", "false_positive"]


class IncidentRequest(BaseModel):
    id: str | None = None
    title: str
    type: str = "unknown"
    severity: str = "medium"
    description: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentUpdateRequest(BaseModel):
    status: str
    notes: str = ""


def _get_supervisor(request: Request):
    supervisor = getattr(request.app.state, "supervisor", None)
    if supervisor is None:
        raise HTTPException(status_code=503, detail="Agent mesh is not initialised")
    return supervisor


@router.post("/respond")
async def respond_to_incident(request: Request, body: IncidentRequest):
    supervisor = _get_supervisor(request)
    return await supervisor._run_agent("incident_response", {
        "incident": body.model_dump(),
        "threat_assessment": body.metadata.get("threat_assessment", {}),
    })


@router.get("/")
async def list_incidents(
    limit: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default=None),
):
    incidents = await repository.list_incidents(limit=limit, status=status)
    source = "postgres"
    if not incidents:
        try:
            incidents = await redis_client.cache.lrange("incidents:index", 0, limit - 1)
        except Exception:
            incidents = []
        source = "redis"
    return {"incidents": incidents, "count": len(incidents), "source": source}


@router.get("/{incident_id}")
async def get_incident(incident_id: str):
    incident = await repository.get_incident(incident_id)
    if incident:
        return incident
    try:
        cached = await redis_client.cache.get(f"incident:{incident_id}")
    except Exception:
        cached = None
    if not cached:
        raise HTTPException(status_code=404, detail="Incident not found")
    return cached


@router.post("/{incident_id}/update")
async def update_incident_status(incident_id: str, body: IncidentUpdateRequest):
    if body.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{body.status}'. Choose from: {VALID_STATUSES}",
        )

    updated = await repository.update_incident(incident_id, body.status, body.notes or None)

    # Keep the Redis mirror consistent for the live dashboard.
    try:
        cached = await redis_client.cache.get(f"incident:{incident_id}")
    except Exception:
        cached = None
    if isinstance(cached, dict):
        cached["status"] = body.status
        if body.notes:
            cached.setdefault("notes", []).append(body.notes)
        try:
            await redis_client.cache.set(f"incident:{incident_id}", cached, ttl=86400)
        except Exception:
            pass

    if updated is None and cached is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        await redis_client.cache.publish(
            "incident_updates", {"incident_id": incident_id, "status": body.status}
        )
    except Exception:
        pass
    return {"ok": True, "incident_id": incident_id, "status": body.status, "incident": updated}
