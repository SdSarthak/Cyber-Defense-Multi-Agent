from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Any
from core.database.redis_client import cache

router = APIRouter()


class ReportRequest(BaseModel):
    report_type: str = "executive"
    period: str | None = None
    data: dict[str, Any] = {}


@router.post("/generate")
async def generate_report(request: Request, body: ReportRequest):
    supervisor = request.app.state.supervisor
    result = await supervisor._run_agent("reporting", {
        "report_type": body.report_type,
        "period": body.period,
        **body.data,
    })
    return result


@router.get("/")
async def list_reports(limit: int = 20):
    index = await cache.lrange("reports:index", 0, limit - 1)
    return {"reports": index, "count": len(index)}


@router.get("/{report_key:path}")
async def get_report(report_key: str):
    data = await cache.get(report_key)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
    return data
