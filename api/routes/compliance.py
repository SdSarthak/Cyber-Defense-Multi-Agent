from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from agents.compliance.agent import FRAMEWORKS
from core.database import repository

router = APIRouter()

SUPPORTED_FRAMEWORKS = list(FRAMEWORKS.keys())


class ComplianceRequest(BaseModel):
    framework: str = "SOC2"
    evidence: dict[str, Any] = Field(default_factory=dict)


def _get_supervisor(request: Request):
    supervisor = getattr(request.app.state, "supervisor", None)
    if supervisor is None:
        raise HTTPException(status_code=503, detail="Agent mesh is not initialised")
    return supervisor


@router.post("/evaluate")
async def evaluate_compliance(request: Request, body: ComplianceRequest):
    if body.framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework. Choose from: {SUPPORTED_FRAMEWORKS}",
        )
    supervisor = _get_supervisor(request)
    return await supervisor._run_agent("compliance", body.model_dump())


@router.get("/frameworks")
async def list_frameworks():
    return {
        "frameworks": SUPPORTED_FRAMEWORKS,
        "controls": {name: len(controls) for name, controls in FRAMEWORKS.items()},
    }


@router.get("/frameworks/{framework}")
async def get_framework_controls(framework: str):
    if framework not in FRAMEWORKS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown framework '{framework}'. Choose from: {SUPPORTED_FRAMEWORKS}",
        )
    return {"framework": framework, "controls": FRAMEWORKS[framework]}


@router.get("/history")
async def get_compliance_history(
    framework: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    """Historical control evaluations recorded in PostgreSQL."""
    if framework and framework not in FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework. Choose from: {SUPPORTED_FRAMEWORKS}",
        )
    checks = await repository.compliance_history(framework=framework, limit=limit)
    return {"checks": checks, "count": len(checks)}
