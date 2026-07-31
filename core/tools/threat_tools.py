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

# RDAP is a blocking library call handed to the default thread pool. ipwhois defaults
# to retry_count=3 and rate_limit_timeout=120, i.e. up to several minutes of `sleep()`
# inside a pooled worker — enough to starve every other `run_in_executor`/`to_thread`
# user in the process (including the readiness probe) during an enrichment burst.
RDAP_SOCKET_TIMEOUT = 5
RDAP_RATE_LIMIT_TIMEOUT = 10
RDAP_TOTAL_TIMEOUT = 20.0

_HIGH_RISK_COUNTRIES = ("RU", "CN", "KP", "IR", "BY")
_HIGH_RISK_ORG_KEYWORDS = ("HOSTING", "VPN", "TOR", "BULLETPROOF", "ANONYMOUS")


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _rdap_lookup(ip: str) -> dict:
    return IPWhois(ip, timeout=RDAP_SOCKET_TIMEOUT).lookup_rdap(
        depth=1, retry_count=1, rate_limit_timeout=RDAP_RATE_LIMIT_TIMEOUT
    )


@tool
async def enrich_ip(ip: str) -> str:
    """Enrich an IP address using RDAP/WHOIS (ipwhois — no API key). Returns ASN, org, country, and risk score."""
    if not isinstance(ip, str) or not ip.strip():
        return json.dumps({"ip": ip, "error": "no IP supplied", "risk_score": 0})
    ip = ip.strip()
    if _is_private(ip):
        return json.dumps({"ip": ip, "type": "private", "risk_score": 0, "org": "internal", "country": None, "asn": None})
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return json.dumps({"ip": ip, "error": "not an IP address", "risk_score": 0})

    try:
        loop = asyncio.get_running_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _rdap_lookup, ip), timeout=RDAP_TOTAL_TIMEOUT
        )
    except asyncio.TimeoutError:
        return json.dumps({"ip": ip, "error": "RDAP lookup timed out", "risk_score": 0})
    except Exception as e:
        return json.dumps({"ip": ip, "error": str(e), "risk_score": 0})

    if not isinstance(result, dict):
        return json.dumps({"ip": ip, "error": "malformed RDAP response", "risk_score": 0})

    # RDAP records routinely carry explicit nulls; `.get(key, "")` still returns None
    # for those, and `None.upper()` used to blow the whole enrichment into the error
    # branch — silently reporting risk_score 0 for a host that was never scored.
    asn = result.get("asn") or ""
    org = result.get("asn_description") or ""
    country = result.get("asn_country_code") or ""
    network = (result.get("network") or {}).get("cidr") or ""

    risk_score = 0
    if asn in _SUSPICIOUS_ASNS:
        risk_score += 60
    if country in _HIGH_RISK_COUNTRIES:
        risk_score += 20
    if any(kw in org.upper() for kw in _HIGH_RISK_ORG_KEYWORDS):
        risk_score += 20
    return json.dumps({
        "ip": ip, "asn": asn, "org": org, "country": country,
        "network": network, "risk_score": min(risk_score, 100),
        "suspicious_asn": asn in _SUSPICIOUS_ASNS,
    })


@tool
async def score_ioc(ioc: str) -> str:
    """Heuristic-only IOC scorer — no external calls. Scores IPs, domains, and file hashes."""
    result: dict = {"ioc": ioc, "type": "unknown", "risk_score": 0, "flags": []}
    if not isinstance(ioc, str) or not ioc.strip():
        result["flags"].append("empty")
        return json.dumps(result)
    ioc = ioc.strip()
    result["ioc"] = ioc
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


# NVD publishes scores under several metric keys and drops the older ones over time.
# Only V31 was read before, so any CVE scored solely under CVSS 3.0 or 2.0 — a large
# slice of pre-2019 records — came back with a null score and null severity, and the
# vulnerability agent then treated a 9.8 RCE as unscored.
_NVD_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _first_metric(metrics: dict) -> dict:
    """Return the highest-precedence CVSS metric entry present, or {}."""
    if not isinstance(metrics, dict):
        return {}
    for key in _NVD_METRIC_KEYS:
        entries = metrics.get(key)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and isinstance(entry.get("cvssData"), dict):
                    return entry
    return {}


def _english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for d in descriptions:
        if isinstance(d, dict) and d.get("lang") == "en":
            return d.get("value") or ""
    for d in descriptions:
        if isinstance(d, dict) and d.get("value"):
            return d["value"]
    return ""


@tool
async def get_nvd_cve(cve_id: str) -> str:
    """Fetch CVE details from the NIST NVD REST API (public, no key required)."""
    if not isinstance(cve_id, str) or not cve_id.strip():
        return json.dumps({"error": "no CVE id supplied", "cve_id": cve_id})
    cve_id = cve_id.strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, params={"cveId": cve_id}, timeout=aiohttp.ClientTimeout(total=15)
            ) as r:
                # NVD answers rate limiting and outages with an HTML body, so a bare
                # `await r.json()` raised ContentTypeError and the caller saw a
                # mimetype complaint instead of "you are being throttled".
                if r.status == 404:
                    return json.dumps({"error": "CVE not found", "cve_id": cve_id})
                if r.status in (403, 429):
                    return json.dumps({
                        "error": "NVD rate limit reached — retry in ~30s",
                        "cve_id": cve_id, "status": r.status,
                    })
                if r.status >= 400:
                    return json.dumps({
                        "error": f"NVD returned HTTP {r.status}", "cve_id": cve_id,
                        "status": r.status,
                    })
                try:
                    data = await r.json(content_type=None)
                except (ValueError, aiohttp.ClientError):
                    return json.dumps({
                        "error": "NVD returned a non-JSON body", "cve_id": cve_id,
                    })
    except asyncio.TimeoutError:
        return json.dumps({"error": "NVD request timed out", "cve_id": cve_id})
    except Exception as e:
        return json.dumps({"error": str(e), "cve_id": cve_id})

    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not vulns or not isinstance(vulns, list):
        return json.dumps({"error": "CVE not found", "cve_id": cve_id})
    cve = vulns[0].get("cve") if isinstance(vulns[0], dict) else None
    if not isinstance(cve, dict):
        return json.dumps({"error": "CVE not found", "cve_id": cve_id})

    metric = _first_metric(cve.get("metrics"))
    cvss = metric.get("cvssData") or {}
    return json.dumps({
        "cve_id": cve.get("id") or cve_id,
        "description": _english_description(cve),
        "cvss_score": cvss.get("baseScore"),
        # CVSS v2 carries the qualitative band on the wrapping metric entry rather
        # than inside cvssData, so read both before giving up.
        "severity": cvss.get("baseSeverity") or metric.get("baseSeverity"),
        "vector": cvss.get("vectorString"),
        "published": cve.get("published"),
    })


@tool
async def scan_asset_ports(ip: str) -> str:
    """Light async TCP port probe on common security-relevant ports. No external APIs needed."""
    # The target comes out of LLM output, so restrict it to a literal address: a
    # hostname here would turn the tool into an arbitrary-host connector (and a DNS
    # lookup for an attacker-chosen name).
    if not isinstance(ip, str):
        return json.dumps({"ip": ip, "error": "not an IP address", "risk_level": "unknown"})
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return json.dumps({"ip": ip, "error": "not an IP address", "risk_level": "unknown"})

    open_ports: list[int] = []

    async def _probe(port: int) -> None:
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=2.0
            )
            # Record the hit as soon as the handshake succeeds: a failure while
            # tearing the socket down used to make an open port read as closed.
            open_ports.append(port)
        except Exception:
            return
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
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
