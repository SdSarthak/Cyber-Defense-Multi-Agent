"""LangChain tools that agents can call for external threat intelligence."""
from __future__ import annotations
import asyncio
import ipaddress
from typing import Optional
import aiohttp
from langchain_core.tools import tool
from core.config import settings


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


@tool
async def check_ip_reputation(ip: str) -> dict:
    """Check an IP address against AbuseIPDB for known malicious activity."""
    if not _is_valid_ip(ip):
        return {"error": "Invalid IP address"}
    if not settings.abuseipdb_api_key:
        return {"ip": ip, "simulated": True, "abuse_confidence": 0, "reports": 0}

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("data", {})
            return {"error": f"API returned {resp.status}"}


@tool
async def lookup_cve(cve_id: str) -> dict:
    """Look up CVE details from the NVD (National Vulnerability Database)."""
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve = vulns[0].get("cve", {})
                    descriptions = cve.get("descriptions", [])
                    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                    metrics = cve.get("metrics", {})
                    cvss_data = {}
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                    return {
                        "cve_id": cve_id,
                        "description": desc,
                        "cvss_score": cvss_data.get("baseScore"),
                        "cvss_vector": cvss_data.get("vectorString"),
                        "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                    }
            return {"error": f"CVE {cve_id} not found", "cve_id": cve_id}


@tool
async def check_virustotal_hash(file_hash: str) -> dict:
    """Check a file hash (MD5/SHA1/SHA256) against VirusTotal."""
    if not settings.virustotal_api_key:
        return {"hash": file_hash, "simulated": True, "malicious": 0, "total": 72}

    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": settings.virustotal_api_key},
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "hash": file_hash,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "total": sum(stats.values()),
                }
            return {"error": f"Hash not found or API error {resp.status}"}


@tool
async def get_mitre_technique(technique_id: str) -> dict:
    """Retrieve MITRE ATT&CK technique details by technique ID (e.g. T1059)."""
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"https://attack.mitre.org/techniques/{technique_id}/",
            headers={"Accept": "application/json"},
        ) as resp:
            # MITRE website doesn't have a clean API; return structured stub
            return {
                "technique_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id}/",
                "note": "Query the MITRE ATT&CK STIX API or local CTI feed for full details",
            }


@tool
def classify_threat_severity(
    confidence: float,
    source_reputation: float,
    affected_critical_asset: bool,
    exploit_available: bool,
) -> str:
    """Classify overall threat severity from multiple risk factors. Returns: critical/high/medium/low."""
    score = confidence * 0.4 + source_reputation * 0.3
    if affected_critical_asset:
        score += 0.2
    if exploit_available:
        score += 0.1

    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


THREAT_INTEL_TOOLS = [
    check_ip_reputation,
    lookup_cve,
    check_virustotal_hash,
    get_mitre_technique,
    classify_threat_severity,
]
