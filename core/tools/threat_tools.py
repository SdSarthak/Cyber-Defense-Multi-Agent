"""
Threat intel tools — zero external API keys required.
- IP enrichment : ipwhois (WHOIS/ASN via RDAP, free)
- IP heuristics : local scoring based on ASN, range, known bad patterns
- CVE lookup    : NIST NVD REST API (public, no key)
- Port scan     : direct async TCP probe
"""
import asyncio
import json
import ipaddress
import aiohttp
from ipwhois import IPWhois
from langchain_core.tools import tool

# Known malicious/high-risk ASNs (Tor exit nodes, bulletproof hosters)
_SUSPICIOUS_ASNS = {
    "AS60068", "AS49453", "AS206728", "AS9009", "AS20473",
    "AS16276", "AS14061", "AS51167", "AS202425", "AS209588",
}

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

_RISK_PORTS = {
    22: "SSH", 23: "Telnet", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}

_COMMON_PORTS = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


@tool
async def enrich_ip(ip: str) -> str:
    """Enrich an IP address using RDAP/WHOIS (ipwhois — no API key). Returns ASN, org, country, and risk score."""
    if _is_private(ip):
        return json.dumps({"ip": ip, "type": "private", "risk_score": 0, "org": "internal", "country": None, "asn": None})
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: IPWhois(ip).lookup_rdap(depth=1))
        asn = result.get("asn", "")
        org = result.get("asn_description", "")
        country = result.get("asn_country_code", "")
        network = result.get("network", {}).get("cidr", "")
        risk_score = 0
        if asn in _SUSPICIOUS_ASNS:
            risk_score += 60
        if country in ("RU", "CN", "KP", "IR", "BY"):
            risk_score += 20
        if any(kw in org.upper() for kw in ("HOSTING", "VPN", "TOR", "BULLETPROOF", "ANONYMOUS")):
            risk_score += 20
        return json.dumps({
            "ip": ip, "asn": asn, "org": org, "country": country,
            "network": network, "risk_score": min(risk_score, 100),
            "suspicious_asn": asn in _SUSPICIOUS_ASNS,
        })
    except Exception as e:
        return json.dumps({"ip": ip, "error": str(e), "risk_score": 0})


@tool
async def score_ioc(ioc: str) -> str:
    """Heuristic-only IOC scorer — no external calls. Scores IPs, domains, and file hashes."""
    result: dict = {"ioc": ioc, "type": "unknown", "risk_score": 0, "flags": []}
    try:
        ipaddress.ip_address(ioc)
        result["type"] = "ip"
        if _is_private(ioc):
            result["flags"].append("private_ip")
        else:
            result["risk_score"] += 10
    except ValueError:
        pass

    if "." in ioc and result["type"] == "unknown":
        result["type"] = "domain"
        if any(tld in ioc for tld in [".tk", ".ml", ".ga", ".cf", ".gq"]):
            result["risk_score"] += 40
            result["flags"].append("free_tld")
        if len(ioc.replace(".", "")) > 30:
            result["risk_score"] += 20
            result["flags"].append("long_domain")
        if ioc.count("-") > 3:
            result["risk_score"] += 15
            result["flags"].append("many_hyphens")
        if any(kw in ioc.lower() for kw in ["update", "secure", "login", "verify", "account", "paypal", "microsoft"]):
            result["risk_score"] += 30
            result["flags"].append("phishing_keyword")

    if result["type"] == "unknown" and all(c in "0123456789abcdefABCDEF" for c in ioc):
        if len(ioc) in (32, 40, 64):
            result["type"] = "hash"
            result["risk_score"] = 50

    result["risk_score"] = min(result["risk_score"], 100)
    return json.dumps(result)


@tool
async def get_nvd_cve(cve_id: str) -> str:
    """Fetch CVE details from the NIST NVD REST API (public, no key required)."""
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


@tool
async def scan_asset_ports(ip: str) -> str:
    """Light async TCP port probe on common security-relevant ports. No external APIs needed."""
    open_ports: list[int] = []

    async def _probe(port: int) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except Exception:
            pass

    await asyncio.gather(*[_probe(p) for p in _COMMON_PORTS])
    exposed_services = [_RISK_PORTS[p] for p in open_ports if p in _RISK_PORTS]
    return json.dumps({
        "ip": ip,
        "open_ports": sorted(open_ports),
        "exposed_services": exposed_services,
        "risk_level": "high" if exposed_services else ("medium" if open_ports else "low"),
    })


THREAT_TOOLS = [enrich_ip, score_ioc, get_nvd_cve, scan_asset_ports]
