"""Supervisor routing, task shaping, escalation handling and threat-level policy."""
from unittest.mock import AsyncMock

import pytest
from langchain_core.runnables import Runnable

from agents.base_agent import BaseSecurityAgent
from core import threat_level
from tests.conftest import patch_llm


def build_supervisor(router_response):
    from agents.supervisor.agent import SupervisorAgent
    with patch_llm(router_response):
        sup = SupervisorAgent()
        _ = sup.llm
    sup._run_agent = AsyncMock(return_value={"summary": "ok", "incident_id": "inc-1"})
    return sup


@pytest.fixture
def supervisor(fake_cache):
    return build_supervisor({"agents": ["threat_detection"], "reasoning": "r",
                             "priority": "high", "parallel": True})


ESCALATION = {
    "agent": "threat_detection", "severity": "High", "threat_type": "brute_force",
    "event": {"source_ip": "203.0.113.5", "destination_ip": "10.0.0.2"},
    "event_id": "6f0f6c38-3c43-4b58-9a58-0b5a0a6f1d11",
}


# ── Escalations ───────────────────────────────────────────────────────────────

def test_escalation_key_is_per_attacker_not_per_agent(supervisor):
    key = supervisor._escalation_key
    from_detector = {"agent": "threat_detection", "threat_type": "brute_force",
                     "event": {"source_ip": "1.2.3.4"}}
    from_logs = {"agent": "log_analysis", "threat_type": "Brute Force",
                 "anomaly": {"source": "1.2.3.4"}}
    other_attacker = {**from_detector, "event": {"source_ip": "5.6.7.8"}}
    assert key(from_detector) == key(from_logs)
    assert key(from_detector) != key(other_attacker)


async def test_escalation_opens_an_incident_linked_to_its_event(supervisor, fake_cache):
    await supervisor.handle_escalation(ESCALATION)
    name, task = supervisor._run_agent.call_args_list[0].args
    assert name == "incident_response"
    assert task["threat_event_ids"] == [ESCALATION["event_id"]]
    assert task["incident"]["affected_assets"] == ["203.0.113.5", "10.0.0.2"]
    assert task["incident"]["severity"] == "high"
    assert fake_cache.store["blackboard:threat_level"] == "high"


async def test_repeat_escalation_within_cooldown_is_suppressed(supervisor):
    await supervisor.handle_escalation(ESCALATION)
    assert await supervisor.handle_escalation({**ESCALATION, "agent": "log_analysis"}) is None
    assert supervisor._run_agent.await_count == 1


async def test_paused_supervisor_does_not_auto_respond(supervisor, fake_cache):
    await BaseSecurityAgent.pause("supervisor")
    assert await supervisor.handle_escalation(ESCALATION) is None
    supervisor._run_agent.assert_not_awaited()
    assert fake_cache.messages_on("agent_events")[-1]["event"] == "escalation_skipped"


async def test_lower_severity_escalation_does_not_lower_the_level(supervisor, fake_cache):
    await threat_level.propose("critical", "escalation")
    await supervisor.handle_escalation({**ESCALATION, "severity": "medium",
                                        "event": {"source_ip": "198.51.100.1"}})
    assert fake_cache.store["blackboard:threat_level"] == "critical"


# ── Mesh runs ─────────────────────────────────────────────────────────────────

async def test_quiet_run_does_not_undo_a_fresh_critical(supervisor, fake_cache):
    await threat_level.propose("critical", "escalation")
    supervisor._run_agent = AsyncMock(return_value={"summary": "nothing", "severity": "low"})
    result = await supervisor.run({"message": "routine"})
    assert result["final_report"]["threat_level"] == "critical"


async def test_dispatch_skips_agents_with_nothing_to_do(fake_cache):
    sup = build_supervisor({"agents": ["all"], "reasoning": "r", "priority": "normal",
                            "parallel": "false"})
    result = await sup.run({"message": "routine check"})
    results = result["agent_results"]
    assert results["log_analysis"]["skipped"] is True
    assert results["vulnerability_intel"]["skipped"] is True
    called = {c.args[0] for c in sup._run_agent.call_args_list}
    assert "log_analysis" not in called and "vulnerability_intel" not in called
    assert {"threat_detection", "incident_response", "compliance", "reporting"} <= called


class _FailingModel(Runnable):
    def invoke(self, *a, **k):
        raise RuntimeError("429 quota exceeded")

    async def ainvoke(self, *a, **k):
        raise RuntimeError("429 quota exceeded")


async def test_router_outage_falls_back_to_task_shape(supervisor):
    supervisor._llm = _FailingModel()
    result = await supervisor.run({"logs": [{"message": "x"}], "framework": "SOC2"})
    assert result["routing_decision"]["agents"] == ["log_analysis", "compliance"]
    assert "router unavailable" in result["routing_decision"]["reasoning"]


def test_task_shaping(supervisor):
    shape = supervisor._task_for
    assert shape("log_analysis", {"message": "x"}) is None
    assert shape("log_analysis", {"logs": [{"m": 1}]})["logs"] == [{"m": 1}]
    assert shape("vulnerability_intel", {"note": "patch cve-2021-44228"}) == {
        "cve_ids": ["CVE-2021-44228"], "asset_ips": [],
    }
    assert shape("compliance", {"framework": "nope"})["framework"] == "SOC2"
    assert shape("reporting", {"report_type": "threat"})["report_type"] == "threat"
    incident = shape("incident_response", {"title": "t", "source_ip": "1.2.3.4"})["incident"]
    assert incident["title"] == "t" and incident["affected_assets"] == ["1.2.3.4"]
    assert shape("threat_detection", {"event": {"source_ip": "1.2.3.4"}}) == {"source_ip": "1.2.3.4"}
