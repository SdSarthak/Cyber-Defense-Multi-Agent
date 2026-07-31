from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from agents.base_agent import BaseSecurityAgent
from api.middleware.auth import require_admin
from core.database import redis_client, repository

router = APIRouter()


class TaskRequest(BaseModel):
    agent: str
    payload: dict[str, Any] = {}


AGENT_MAP = {
    "threat_detection": "ThreatDetectionAgent",
    "log_analysis": "LogAnalysisAgent",
    "vulnerability_intel": "VulnerabilityIntelAgent",
    "incident_response": "IncidentResponseAgent",
    "compliance": "ComplianceAgent",
    "reporting": "ReportingAgent",
    "supervisor": "SupervisorAgent",
}


def _get_supervisor(request: Request):
    supervisor = getattr(request.app.state, "supervisor", None)
    if supervisor is None:
        raise HTTPException(status_code=503, detail="Agent mesh is not initialised")
    return supervisor


async def _status_for(name: str) -> dict:
    try:
        raw = await redis_client.cache.hgetall(f"agent_status:{name}")
    except Exception:
        raw = {}
    status = dict(raw) if raw else {"status": "idle"}
    try:
        status["paused"] = bool(
            await redis_client.cache.exists(f"agent_paused:{name}")
        )
    except Exception:
        status["paused"] = False
    return status


@router.get("/status")
async def get_all_agent_statuses():
    return {name: await _status_for(name) for name in AGENT_MAP}


@router.get("/registry")
async def get_agent_registry():
    """Durable agent statistics (task counts, heartbeats) from PostgreSQL."""
    return {"agents": await repository.list_agent_registry()}


@router.get("/blackboard")
async def get_blackboard():
    keys = ["threat_level", "last_agent_results", "active_incidents"]
    board = {}
    for key in keys:
        try:
            board[key] = await redis_client.cache.get(f"blackboard:{key}")
        except Exception:
            board[key] = None
    return board


@router.post("/run", dependencies=[Depends(require_admin)])
async def run_agent(request: Request, body: TaskRequest):
    if body.agent not in AGENT_MAP:
        raise HTTPException(status_code=400, detail=f"Unknown agent: {body.agent}")
    supervisor = _get_supervisor(request)
    if body.agent == "supervisor":
        return await supervisor._run_with_telemetry(body.payload)
    return await supervisor._run_agent(body.agent, body.payload)


@router.post("/supervisor/run", dependencies=[Depends(require_admin)])
async def run_supervisor(request: Request, payload: dict):
    supervisor = _get_supervisor(request)
    return await supervisor._run_with_telemetry(payload)


@router.post("/{agent_name}/pause", dependencies=[Depends(require_admin)])
async def pause_agent(agent_name: str):
    if agent_name not in AGENT_MAP:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_name}")
    await BaseSecurityAgent.pause(agent_name)
    return {"agent": agent_name, "status": "paused"}


@router.post("/{agent_name}/resume", dependencies=[Depends(require_admin)])
async def resume_agent(agent_name: str):
    if agent_name not in AGENT_MAP:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_name}")
    await BaseSecurityAgent.resume(agent_name)
    return {"agent": agent_name, "status": "idle"}


@router.get("/{agent_name}/status")
async def get_agent_status(agent_name: str):
    if agent_name not in AGENT_MAP:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_name}")
    return await _status_for(agent_name)


@router.get("/{agent_name}/history")
async def get_agent_history(agent_name: str, limit: int = Query(default=20, ge=1, le=200)):
    if agent_name not in AGENT_MAP:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_name}")
    try:
        history = await redis_client.cache.lrange(f"agent:{agent_name}:history", 0, limit - 1)
    except Exception:
        history = []
    return {"agent": agent_name, "history": history}
