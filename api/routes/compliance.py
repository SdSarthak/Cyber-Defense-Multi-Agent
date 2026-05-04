from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Any

router = APIRouter()

SUPPORTED_FRAMEWORKS = ["SOC2", "NIST_CSF", "ISO27001"]


class ComplianceRequest(BaseModel):
    framework: str = "SOC2"
    evidence: dict[str, Any] = {}


@router.post("/evaluate")
async def evaluate_compliance(request: Request, body: ComplianceRequest):
    if body.framework not in SUPPORTED_FRAMEWORKS:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unsupported framework. Choose from: {SUPPORTED_FRAMEWORKS}")
    supervisor = request.app.state.supervisor
    result = await supervisor._run_agent("compliance", body.model_dump())
    return result


@router.get("/frameworks")
async def list_frameworks():
    return {"frameworks": SUPPORTED_FRAMEWORKS}
