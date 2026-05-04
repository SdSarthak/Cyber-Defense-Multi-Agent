from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Any
from core.database.redis_client import cache

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


@router.get("/status")
async def get_all_agent_statuses():
    statuses = {}
    for name in AGENT_MAP:
        raw = await cache.hgetall(f"agent_status:{name}")
        statuses[name] = raw or {"status": "idle"}
    return statuses


@router.get("/{agent_name}/status")
async def get_agent_status(agent_name: str):
    if agent_name not in AGENT_MAP:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_name}")
    raw = await cache.hgetall(f"agent_status:{agent_name}")
    return raw or {"status": "idle"}


@router.get("/{agent_name}/history")
async def get_agent_history(agent_name: str, limit: int = 20):
    if agent_name not in AGENT_MAP:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_name}")
    history = await cache.lrange(f"agent:{agent_name}:history", 0, limit - 1)
    return {"agent": agent_name, "history": history}


@router.post("/run")
async def run_agent(request: Request, body: TaskRequest):
    if body.agent not in AGENT_MAP:
        raise HTTPException(status_code=400, detail=f"Unknown agent: {body.agent}")
    supervisor = request.app.state.supervisor
    if body.agent == "supervisor":
        result = await supervisor._run_with_telemetry(body.payload)
    else:
        result = await supervisor._run_agent(body.agent, body.payload)
    return result


@router.post("/supervisor/run")
async def run_supervisor(request: Request, payload: dict):
    supervisor = request.app.state.supervisor
    result = await supervisor._run_with_telemetry(payload)
    return result


@router.get("/blackboard")
async def get_blackboard():
    keys = ["threat_level", "last_agent_results", "active_incidents"]
    board = {}
    for key in keys:
        board[key] = await cache.get(f"blackboard:{key}")
    return board
