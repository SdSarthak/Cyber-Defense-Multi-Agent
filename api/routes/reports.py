from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.database import redis_client

router = APIRouter()

REPORT_TYPES = ["executive", "threat"]


class ReportRequest(BaseModel):
    report_type: str = "executive"
    period: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


def _get_supervisor(request: Request):
    supervisor = getattr(request.app.state, "supervisor", None)
    if supervisor is None:
        raise HTTPException(status_code=503, detail="Agent mesh is not initialised")
    return supervisor


@router.post("/generate")
async def generate_report(request: Request, body: ReportRequest):
    if body.report_type not in REPORT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported report_type. Choose from: {REPORT_TYPES}",
        )
    supervisor = _get_supervisor(request)
    return await supervisor._run_agent("reporting", {
        "report_type": body.report_type,
        "period": body.period,
        **body.data,
    })


@router.get("/")
async def list_reports(limit: int = Query(default=20, le=100)):
    try:
        index = await redis_client.cache.lrange("reports:index", 0, limit - 1)
    except Exception:
        index = []
    return {"reports": index, "count": len(index)}


@router.get("/{report_key:path}")
async def get_report(report_key: str):
    # Only report:* keys are addressable — otherwise this endpoint would read any
    # key in Redis, including agent state and blackboard entries.
    if not report_key.startswith("report:"):
        raise HTTPException(status_code=400, detail="Report keys must start with 'report:'")
    try:
        data = await redis_client.cache.get(report_key)
    except Exception:
        data = None
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
    return data
