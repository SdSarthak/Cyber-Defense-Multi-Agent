"""Shared LangChain tools available to agents for external threat intel lookups."""
import json
import aiohttp
from langchain_core.tools import tool
from core.config import settings


@tool
async def lookup_ip_reputation(ip: str) -> str:
    """Check reputation of an IP address using AbuseIPDB."""
    if not settings.abuseipdb_api_key:
        return json.dumps({"error": "AbuseIPDB key not configured", "ip": ip})
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=10)) as r:
                data = await r.json()
                d = data.get("data", {})
                return json.dumps({
                    "ip": ip,
                    "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "total_reports": d.get("totalReports", 0),
                    "is_tor": d.get("isTor", False),
                    "last_reported": d.get("lastReportedAt"),
                })
    except Exception as e:
        return json.dumps({"error": str(e), "ip": ip})


@tool
async def lookup_virustotal(ioc: str) -> str:
    """Check a file hash, URL, domain, or IP against VirusTotal."""
    if not settings.virustotal_api_key:
        return json.dumps({"error": "VirusTotal key not configured", "ioc": ioc})
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                data = await r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return json.dumps({
                    "ioc": ioc,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                })
    except Exception as e:
        return json.dumps({"error": str(e), "ioc": ioc})


@tool
async def search_shodan(query: str) -> str:
    """Search Shodan for exposed hosts matching a query string."""
    if not settings.shodan_api_key:
        return json.dumps({"error": "Shodan key not configured"})
    url = "https://api.shodan.io/shodan/host/search"
    params = {"key": settings.shodan_api_key, "query": query, "minify": True}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as r:
                data = await r.json()
                matches = data.get("matches", [])[:5]
                results = [
                    {
                        "ip": m.get("ip_str"),
                        "port": m.get("port"),
                        "org": m.get("org"),
                        "country": m.get("location", {}).get("country_name"),
                        "product": m.get("product"),
                    }
                    for m in matches
                ]
                return json.dumps({"query": query, "total": data.get("total", 0), "results": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
async def get_nvd_cve(cve_id: str) -> str:
    """Fetch CVE details from the NIST NVD (no key required)."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                data = await r.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return json.dumps({"error": "CVE not found", "cve_id": cve_id})
                cve = vulns[0]["cve"]
                metrics = cve.get("metrics", {})
                cvss = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                )
                return json.dumps({
                    "cve_id": cve_id,
                    "description": cve.get("descriptions", [{}])[0].get("value", ""),
                    "cvss_score": cvss.get("baseScore"),
                    "severity": cvss.get("baseSeverity"),
                    "vector": cvss.get("vectorString"),
                    "published": cve.get("published"),
                })
    except Exception as e:
        return json.dumps({"error": str(e), "cve_id": cve_id})


THREAT_TOOLS = [lookup_ip_reputation, lookup_virustotal, search_shodan, get_nvd_cve]
