from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core import containment
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


# ── Containment approval ──────────────────────────────────────────────────────

async def _load_actions(incident_id: str) -> tuple[list, dict | None, dict | None]:
    """(actions, postgres row, redis record) for an incident; actions empty when unknown."""
    row = await repository.get_incident(incident_id)
    try:
        cached = await redis_client.cache.get(f"incident:{incident_id}")
    except Exception:
        cached = None
    cached = cached if isinstance(cached, dict) else None
    if row:
        return list(row.get("remediation_steps") or []), row, cached
    if cached:
        return list((cached.get("response_plan") or {}).get("containment_actions") or []), None, cached
    return [], None, None


async def _set_action(incident_id: str, index: int, status: str, result: dict | None,
                      row: dict | None, cached: dict | None) -> dict | None:
    updated = None
    if row:
        updated = await repository.update_containment_action(incident_id, index, status, result)
    if cached:
        actions = (cached.get("response_plan") or {}).get("containment_actions") or []
        if 0 <= index < len(actions) and isinstance(actions[index], dict):
            actions[index]["status"] = status
            if result is not None:
                actions[index]["result"] = result
            updated = updated or actions[index]
            try:
                await redis_client.cache.set(f"incident:{incident_id}", cached, ttl=86400)
            except Exception:
                pass
    return updated


async def _decide(incident_id: str, action_index: int, approve: bool) -> dict:
    actions, row, cached = await _load_actions(incident_id)
    if not row and not cached:
        raise HTTPException(status_code=404, detail="Incident not found")
    if not 0 <= action_index < len(actions) or not isinstance(actions[action_index], dict):
        raise HTTPException(status_code=404, detail=f"No containment action at index {action_index}")
    action = actions[action_index]
    if not action.get("automated") or action.get("status") not in containment.APPROVABLE_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=f"Action is '{action.get('status')}', not awaiting approval",
        )

    if approve:
        context = {**(cached or {}), **(row or {}), "id": incident_id}
        result = await containment.execute(str(action.get("action", "")), context)
        status, outcome = result["status"], result
    else:
        status, outcome = "rejected", None

    updated = await _set_action(incident_id, action_index, status, outcome, row, cached)
    try:
        await redis_client.cache.publish("incident_updates", {
            "incident_id": incident_id, "action_index": action_index, "action_status": status,
        })
    except Exception:
        pass
    return {"ok": True, "action": updated or {**action, "status": status}}


@router.post("/{incident_id}/actions/{action_index}/approve")
async def approve_containment_action(incident_id: str, action_index: int):
    """Execute an automated containment action that is awaiting approval (admin)."""
    return await _decide(incident_id, action_index, approve=True)


@router.post("/{incident_id}/actions/{action_index}/reject")
async def reject_containment_action(incident_id: str, action_index: int):
    """Decline an automated containment action that is awaiting approval (admin)."""
    return await _decide(incident_id, action_index, approve=False)
