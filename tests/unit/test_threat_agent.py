"""Unit tests for ThreatDetectionAgent."""
import json

import pytest

from tests.conftest import patch_llm

PORT_SCAN_VERDICT = {
    "threat_type": "port_scan", "severity": "high", "confidence": 0.9,
    "indicators": ["185.220.101.45"], "mitre_tactics": ["Reconnaissance"],
    "mitre_techniques": ["T1046"], "reasoning": "Port scan detected",
    "should_escalate": True,
}


def build_agent(response):
    """Construct a ThreatDetectionAgent whose LLM returns `response`."""
    from agents.threat_detection.agent import ThreatDetectionAgent
    agent = ThreatDetectionAgent()
    with patch_llm(response):
        # Force the lazy LLM to materialise while the patch is active.
        _ = agent.llm
    return agent


@pytest.fixture
def threat_agent(fake_cache):
    return build_agent(PORT_SCAN_VERDICT)


async def test_threat_agent_returns_assessment(threat_agent):
    result = await threat_agent.run({
        "source_ip": "185.220.101.45",
        "destination_ip": "10.0.1.50",
        "message": "Port scan from 185.220.101.45",
    })
    assert result["threat_assessment"]["threat_type"] == "port_scan"
    assert result["severity"] == "high"
    assert "PORT_SCAN" in result["summary"]


async def test_threat_agent_escalates_high_severity(threat_agent, fake_cache):
    await threat_agent.run({"source_ip": "185.220.101.45", "message": "Critical threat"})
    escalations = fake_cache.messages_on("escalations")
    assert len(escalations) == 1
    assert escalations[0]["agent"] == "threat_detection"
    assert escalations[0]["threat_type"] == "port_scan"


async def test_threat_agent_handles_empty_event(threat_agent):
    result = await threat_agent.run({})
    assert "threat_assessment" in result


async def test_threat_agent_handles_malformed_llm_json(fake_cache):
    agent = build_agent("NOT JSON AT ALL {broken")
    result = await agent.run({"message": "test"})
    assert result["threat_assessment"]["threat_type"] == "unknown"
    assert result["severity"] == "medium"


async def test_threat_agent_parses_fenced_json(fake_cache):
    """Gemini frequently wraps JSON in a markdown fence despite the prompt."""
    fenced = "```json\n" + json.dumps(PORT_SCAN_VERDICT) + "\n```"
    agent = build_agent(fenced)
    result = await agent.run({"message": "test"})
    assert result["threat_assessment"]["threat_type"] == "port_scan"
    assert result["severity"] == "high"


async def test_threat_agent_parses_json_with_preamble(fake_cache):
    prose = "Here is my analysis:\n" + json.dumps(PORT_SCAN_VERDICT)
    agent = build_agent(prose)
    result = await agent.run({"message": "test"})
    assert result["threat_assessment"]["threat_type"] == "port_scan"


@pytest.mark.parametrize("severity,should_escalate", [
    ("critical", True),
    ("high", True),
    ("medium", False),
    ("low", False),
])
async def test_escalation_by_severity(severity, should_escalate, fake_cache):
    agent = build_agent({
        "threat_type": "test", "severity": severity, "confidence": 0.8,
        "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
        "reasoning": "test", "should_escalate": False,
    })
    result = await agent.run({"message": "test"})
    assert result["should_escalate"] == should_escalate


async def test_high_confidence_benign_verdict_does_not_escalate(fake_cache):
    """A confident 'nothing to see here' must not page the on-call analyst."""
    agent = build_agent({
        "threat_type": "none", "severity": "info", "confidence": 0.99,
        "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
        "reasoning": "normal traffic", "should_escalate": False,
    })
    result = await agent.run({"message": "GET /health"})
    assert result["should_escalate"] is False
    assert fake_cache.messages_on("escalations") == []


async def test_high_confidence_threat_escalates_without_severity(fake_cache):
    agent = build_agent({
        "threat_type": "c2_beacon", "severity": "medium", "confidence": 0.95,
        "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
        "reasoning": "beaconing", "should_escalate": False,
    })
    result = await agent.run({"message": "beacon"})
    assert result["should_escalate"] is True


async def test_mitre_mapping_is_propagated(threat_agent):
    result = await threat_agent.run({"message": "scan"})
    assert result["mitre_mapping"]["techniques"] == ["T1046"]
    assert result["mitre_mapping"]["tactics"] == ["Reconnaissance"]


async def test_agent_survives_redis_publish_failure(fake_cache):
    async def boom(*args, **kwargs):
        raise ConnectionError("Redis connection lost")

    fake_cache.publish = boom
    agent = build_agent(PORT_SCAN_VERDICT)
    result = await agent.run({"message": "test"})
    assert result["severity"] == "high"


async def test_non_string_indicators_are_ignored(fake_cache):
    """A malformed indicator list must not crash IOC enrichment."""
    agent = build_agent({
        "threat_type": "port_scan", "severity": "low", "confidence": 0.4,
        "indicators": [None, 42, {"nested": "object"}], "mitre_tactics": [],
        "mitre_techniques": [], "reasoning": "x", "should_escalate": False,
    })
    result = await agent.run({"message": "test"})
    assert result["enrichment"] == {}


async def test_paused_agent_skips_work(fake_cache):
    from agents.base_agent import BaseSecurityAgent

    agent = build_agent(PORT_SCAN_VERDICT)
    await BaseSecurityAgent.pause("threat_detection")
    result = await agent._run_with_telemetry({"message": "test"})
    assert result["skipped"] is True
    assert fake_cache.messages_on("escalations") == []

    await BaseSecurityAgent.resume("threat_detection")
    result = await agent._run_with_telemetry({"message": "test"})
    assert result.get("skipped") is not True
