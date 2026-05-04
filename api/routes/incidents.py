from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel
from typing import Any
from core.database.redis_client import cache

router = APIRouter()


class IncidentRequest(BaseModel):
    id: str | None = None
    title: str
    type: str = "unknown"
    severity: str = "medium"
    description: str = ""
    affected_assets: list[str] = []
    metadata: dict[str, Any] = {}


@router.post("/respond")
async def respond_to_incident(request: Request, body: IncidentRequest):
    supervisor = request.app.state.supervisor
    result = await supervisor._run_agent("incident_response", {
        "incident": body.model_dump(),
        "threat_assessment": body.metadata.get("threat_assessment", {}),
    })
    return result


@router.get("/{incident_id}")
async def get_incident(incident_id: str):
    data = await cache.get(f"incident:{incident_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Incident not found")
    return data


@router.get("/")
async def list_incidents(limit: int = Query(default=20, le=100)):
    index = await cache.lrange("incidents:index", 0, limit - 1)
    return {"incidents": index, "count": len(index)}


@router.post("/{incident_id}/update")
async def update_incident_status(incident_id: str, status: str, notes: str = ""):
    existing = await cache.get(f"incident:{incident_id}")
    if not existing:
        raise HTTPException(status_code=404, detail="Incident not found")
    existing["status"] = status
    if notes:
        existing.setdefault("notes", []).append(notes)
    await cache.set(f"incident:{incident_id}", existing, ttl=86400)
    await cache.publish("incident_updates", {"incident_id": incident_id, "status": status})
    return {"ok": True, "incident_id": incident_id, "status": status}
