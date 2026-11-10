"""What the specialist agents record: no invented data, no colliding keys."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.config import settings
from tests.conftest import CANNED_RESPONSES, patch_llm


def _agent(cls_path: str, response):
    module, name = cls_path.rsplit(".", 1)
    cls = getattr(__import__(module, fromlist=[name]), name)
    agent = cls()
    with patch_llm(response):
        _ = agent.llm
    return agent


# ── Containment executors ─────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status):
        self.status = status

    async def text(self):
        return "ok"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Session:
    def __init__(self, status, sent):
        self._status, self._sent = status, sent

    def post(self, url, json=None):
        self._sent.append((url, json))
        return _Resp(self._status)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.mark.parametrize("status,expected", [(200, "completed"), (502, "failed")])
async def test_webhook_executor_reports_what_happened(monkeypatch, status, expected):
    from core import containment
    monkeypatch.setattr(settings, "containment_mode", "webhook")
    monkeypatch.setattr(settings, "containment_webhook_url", "https://soar.example/hook")
    sent: list = []
    with patch.object(containment.aiohttp, "ClientSession", lambda *a, **k: _Session(status, sent)):
        result = await containment.execute("Block 1.2.3.4", {"id": "inc-9", "title": "t"})
    assert result["status"] == expected and result["executor"] == "webhook"
    assert sent == [("https://soar.example/hook",
                     {"action": "Block 1.2.3.4", "incident": {"id": "inc-9", "title": "t"}})]


async def test_simulated_executor_never_claims_completion():
    from core import containment
    result = await containment.execute("Isolate host", {})
    assert result["status"] == "simulated"
    assert "nothing was executed" in result["note"]


# ── Vulnerability intel ───────────────────────────────────────────────────────

async def test_failed_cve_lookups_are_not_analysed_or_stored(fake_cache, monkeypatch):
    from core.database import repository
    agent = _agent("agents.vulnerability_intel.agent.VulnerabilityIntelAgent", CANNED_RESPONSES["vuln"])
    saved = []

    async def fake_save(cve, report):
        saved.append(cve["cve_id"])

    async def fake_nvd(payload):
        if payload["cve_id"] == "CVE-2021-44228":
            return json.dumps({"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "description": "log4shell"})
        return json.dumps({"error": "NVD rate limit reached — retry in ~30s", "cve_id": payload["cve_id"]})

    monkeypatch.setattr(repository, "save_vulnerability", fake_save)
    monkeypatch.setattr("core.tools.threat_tools.get_nvd_cve", SimpleNamespace(ainvoke=fake_nvd))
    result = await agent.run({"cve_ids": ["CVE-2021-44228", "CVE-2020-0001"]})

    assert saved == ["CVE-2021-44228"]
    failed = [r for r in result["risk_reports"] if r.get("error")]
    assert [r["cve_id"] for r in failed] == ["CVE-2020-0001"]
    assert "Lookup failures: 1" in result["summary"]


async def test_asset_only_scans_produce_an_exposure_assessment(fake_cache, monkeypatch):
    agent = _agent("agents.vulnerability_intel.agent.VulnerabilityIntelAgent", CANNED_RESPONSES["vuln"])

    async def fake_scan(payload):
        return json.dumps({"ip": payload["ip"], "open_ports": [22, 6379],
                           "exposed_services": ["SSH", "Redis"], "risk_level": "high"})

    monkeypatch.setattr("core.tools.threat_tools.scan_asset_ports", SimpleNamespace(ainvoke=fake_scan))
    result = await agent.run({"asset_ips": ["10.0.0.5"]})
    (report,) = result["risk_reports"]
    assert report["type"] == "exposure" and report["risk_score"] == 8.0
    assert "Redis" in report["summary"]


# ── Compliance ────────────────────────────────────────────────────────────────

async def test_controls_are_judged_against_collected_evidence(fake_cache):
    agent = _agent("agents.compliance.agent.ComplianceAgent", CANNED_RESPONSES["compliance"])
    result = await agent.run({"framework": "SOC2", "evidence": {"CC8.1": {"change_tickets": 12}}})
    by_id = {r["control_id"]: r for r in result["control_results"]}
    assert by_id["CC6.1"]["evidence"]["platform"]["authentication"].startswith("JWT")
    assert by_id["CC8.1"]["evidence"]["platform"]["collected"] is False
    assert by_id["CC8.1"]["evidence"]["provided"] == {"change_tickets": 12}
    assert result["evaluation_id"]
    # The prompt saw the evidence, not an empty object.
    prompt = str(agent.llm.calls[0])
    assert "websocket_auth_required" in prompt


async def test_unparseable_verdict_is_not_scored(fake_cache):
    agent = _agent("agents.compliance.agent.ComplianceAgent", "no json here")
    result = await agent.run({"framework": "ISO27001"})
    assert all(r["status"] == "na" and r["score"] is None for r in result["control_results"])
    assert result["overall_score"] is None


# ── Reporting ─────────────────────────────────────────────────────────────────

async def test_report_keys_do_not_collide_within_a_second(fake_cache):
    agent = _agent("agents.reporting.agent.ReportingAgent", CANNED_RESPONSES["report"])
    a, b = await asyncio.gather(
        agent.run({"report_type": "executive"}), agent.run({"report_type": "executive"})
    )
    assert a["report_key"] != b["report_key"]
    assert len(await fake_cache.lrange("reports:index", 0, -1)) == 2


async def test_key_metrics_come_from_the_record_not_the_model(fake_cache, monkeypatch):
    from core.database import repository
    monkeypatch.setattr(repository, "enabled", lambda: True)

    async def metrics(hours=0):
        return {"total_incidents": 3, "critical_incidents": 1, "open_incidents": 2,
                "mean_time_to_detect_hours": None, "mean_time_to_respond_hours": 4.5}

    async def empty(*a, **k):
        return {} if k.get("hours") or not a else []

    monkeypatch.setattr(repository, "incident_metrics", metrics)
    monkeypatch.setattr(repository, "threat_severity_counts", lambda hours=24: asyncio.sleep(0, {}))
    monkeypatch.setattr(repository, "recent_threat_events", lambda limit=25: asyncio.sleep(0, []))
    monkeypatch.setattr(repository, "list_vulnerabilities", lambda limit=200: asyncio.sleep(0, [
        {"cve_id": "CVE-1", "severity": "high", "remediation_status": "open"},
    ]))
    monkeypatch.setattr(repository, "compliance_summary", lambda: asyncio.sleep(0, {
        "SOC2": {"score": 80.0}, "ISO27001": {"score": 60.0},
    }))
    agent = _agent("agents.reporting.agent.ReportingAgent", CANNED_RESPONSES["report"])
    report = (await agent.run({"report_type": "executive"}))["report"]
    assert report["key_metrics"] == {
        "total_incidents": 3, "critical_incidents": 1,
        "mean_time_to_detect_hours": None, "mean_time_to_respond_hours": 4.5,
        "vulnerabilities_open": 1, "compliance_score": 70.0,
    }


async def test_large_caller_data_cannot_push_telemetry_out_of_the_prompt(fake_cache):
    agent = _agent("agents.reporting.agent.ReportingAgent", CANNED_RESPONSES["report"])
    await agent.run({"report_type": "executive", "blob": "x" * 50_000})
    prompt = str(agent.llm.calls[0])
    assert "key_metrics" in prompt
    assert prompt.index("telemetry:") < prompt.index("request context:")


# ── Retrieval ─────────────────────────────────────────────────────────────────

class _Doc:
    def __init__(self, text):
        self.page_content = text


class _Retriever:
    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    async def ainvoke(self, question):
        self.calls += 1
        if self.fail:
            raise RuntimeError("embedding model not found")
        return [_Doc("T1110 brute force"), _Doc("T1046 network scan")]


async def test_rag_returns_retrieved_passages_without_an_llm_call(monkeypatch):
    from core.rag import rag_chain
    monkeypatch.setattr(settings, "rag_enabled", True)
    retriever = _Retriever()
    monkeypatch.setattr(rag_chain, "build_retriever", lambda collection, k=5: retriever)
    chain = rag_chain.LazyRagChain("chroma_collection_threats", "test")
    assert await chain.ainvoke("brute force") == "T1110 brute force\n\nT1046 network scan"


async def test_rag_backs_off_after_a_failure(monkeypatch):
    from core.rag import rag_chain
    monkeypatch.setattr(settings, "rag_enabled", True)
    monkeypatch.setattr(settings, "rag_retry_after_seconds", 60)
    retriever = _Retriever(fail=True)
    monkeypatch.setattr(rag_chain, "build_retriever", lambda collection, k=5: retriever)
    chain = rag_chain.LazyRagChain("chroma_collection_threats", "test")
    assert await chain.ainvoke("q") == ""
    assert await chain.ainvoke("q") == ""
    assert retriever.calls == 1
