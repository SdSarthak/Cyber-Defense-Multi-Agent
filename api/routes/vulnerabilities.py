import json
import re

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.database import repository
from core.tools import threat_tools

router = APIRouter()

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class VulnScanRequest(BaseModel):
    cve_ids: list[str] = Field(default_factory=list)
    asset_ips: list[str] = Field(default_factory=list)


def _get_supervisor(request: Request):
    supervisor = getattr(request.app.state, "supervisor", None)
    if supervisor is None:
        raise HTTPException(status_code=503, detail="Agent mesh is not initialised")
    return supervisor


@router.post("/scan")
async def scan_vulnerabilities(request: Request, body: VulnScanRequest):
    if not body.cve_ids and not body.asset_ips:
        raise HTTPException(status_code=400, detail="Supply at least one cve_id or asset_ip")
    invalid = [c for c in body.cve_ids if not CVE_PATTERN.match(c)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Malformed CVE identifiers: {invalid}")
    supervisor = _get_supervisor(request)
    return await supervisor._run_agent("vulnerability_intel", body.model_dump())


@router.get("/")
async def list_vulnerabilities(limit: int = Query(default=50, ge=1, le=200)):
    """Vulnerabilities recorded by previous scans, highest CVSS first."""
    vulns = await repository.list_vulnerabilities(limit=limit)
    return {"vulnerabilities": vulns, "count": len(vulns)}


@router.get("/cve/{cve_id}")
async def get_cve(cve_id: str):
    if not CVE_PATTERN.match(cve_id):
        raise HTTPException(status_code=400, detail=f"Malformed CVE identifier: {cve_id}")
    raw = await threat_tools.get_nvd_cve.ainvoke({"cve_id": cve_id})
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=502, detail="Unexpected response from NVD")
    if data.get("error") == "CVE not found":
        raise HTTPException(status_code=404, detail=f"CVE not found: {cve_id}")
    return data
