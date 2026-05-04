from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class VulnScanRequest(BaseModel):
    cve_ids: list[str] = []
    asset_ips: list[str] = []


@router.post("/scan")
async def scan_vulnerabilities(request: Request, body: VulnScanRequest):
    supervisor = request.app.state.supervisor
    result = await supervisor._run_agent("vulnerability_intel", body.model_dump())
    return result


@router.get("/cve/{cve_id}")
async def get_cve(cve_id: str):
    from core.tools.threat_tools import get_nvd_cve
    import json
    raw = await get_nvd_cve.ainvoke({"cve_id": cve_id})
    return json.loads(raw)
