"""Unit tests for LogAnalysisAgent."""
import pytest

from simulation.log_generators.generators import (
    generate_batch, make_brute_force_log, make_c2_beacon_log, make_web_log,
)
from tests.conftest import patch_llm

LLM_ANALYSIS = {
    "anomaly_count": 2, "total_analyzed": 20,
    "anomalies": [
        {"log_index": 0, "anomaly_type": "brute_force", "severity": "high",
         "source": "185.220.101.45", "description": "50 failed logins", "action": "block_ip"},
        {"log_index": 5, "anomaly_type": "c2_beacon", "severity": "critical",
         "source": "10.0.1.5", "description": "C2 beacon", "action": "isolate"},
    ],
    "patterns_detected": ["brute_force", "c2_beacon"],
    "risk_summary": "Active attack detected",
}


def build_agent(response=LLM_ANALYSIS):
    from agents.log_analysis.agent import LogAnalysisAgent
    agent = LogAnalysisAgent()
    with patch_llm(response):
        _ = agent.llm
    return agent


@pytest.fixture
def log_agent(fake_cache):
    return build_agent()


async def test_log_agent_returns_anomalies(log_agent):
    logs = generate_batch(size=20, attack_probability=0.3)
    result = await log_agent.run({"logs": logs})
    assert len(result["anomalies"]) == 2
    assert "pattern_hits" in result
    assert result["risk_summary"] == "Active attack detected"


async def test_log_agent_empty_input(log_agent):
    result = await log_agent.run({"logs": []})
    assert result["summary"] == "No logs provided"
    assert result["anomalies"] == []


async def test_log_agent_missing_logs_key(log_agent):
    result = await log_agent.run({})
    assert result["summary"] == "No logs provided"


async def test_pattern_scan_detects_brute_force(log_agent):
    logs = [make_brute_force_log() for _ in range(10)]
    result = await log_agent.run({"logs": logs})
    assert "brute_force" in result["pattern_hits"]
    assert len(result["pattern_hits"]["brute_force"]) == 10


async def test_pattern_scan_detects_sql_injection(log_agent):
    logs = [{"message": "GET /?id=1' UNION SELECT password FROM users--"}]
    result = await log_agent.run({"logs": logs})
    assert "sql_injection" in result["pattern_hits"]


async def test_pattern_scan_detects_path_traversal(log_agent):
    logs = [{"message": "GET /../../../etc/passwd"}]
    result = await log_agent.run({"logs": logs})
    assert "path_traversal" in result["pattern_hits"]


async def test_pattern_scan_reads_parsed_fields(log_agent):
    """Attack payloads often live in parsed_fields.path, not the rendered message."""
    logs = [{"message": "request served", "parsed_fields": {"path": "/?q=' OR 1=1--"}}]
    result = await log_agent.run({"logs": logs})
    assert "sql_injection" in result["pattern_hits"]


async def test_web_attack_logs_carry_attack_type(log_agent):
    log = make_web_log(attack=True)
    assert log["parsed_fields"]["attack_type"]


async def test_pattern_scan_ignores_clean_logs(log_agent):
    logs = [{"message": "Accepted password for ubuntu from 10.0.1.5 port 22 ssh2"}]
    result = await log_agent.run({"logs": logs})
    assert result["pattern_hits"] == {}


async def test_anomalies_sorted_by_severity(log_agent):
    logs = generate_batch(size=30, attack_probability=0.5)
    result = await log_agent.run({"logs": logs})
    severities = [a["severity"] for a in result["anomalies"]]
    assert severities == ["critical", "high"]


async def test_high_severity_anomalies_escalate(log_agent, fake_cache):
    logs = [make_c2_beacon_log() for _ in range(5)]
    await log_agent.run({"logs": logs})
    escalations = fake_cache.messages_on("escalations")
    assert len(escalations) == 2
    assert {e["severity"] for e in escalations} == {"critical", "high"}


async def test_low_severity_anomalies_do_not_escalate(fake_cache):
    agent = build_agent({
        "anomaly_count": 1, "total_analyzed": 1,
        "anomalies": [{"log_index": 0, "anomaly_type": "noise", "severity": "low",
                       "source": "10.0.0.1", "description": "", "action": ""}],
        "patterns_detected": [], "risk_summary": "quiet",
    })
    await agent.run({"logs": [{"message": "hello"}]})
    assert fake_cache.messages_on("escalations") == []


async def test_large_batch_truncated_gracefully(log_agent):
    logs = generate_batch(size=200, attack_probability=0.1)
    result = await log_agent.run({"logs": logs})
    assert "anomalies" in result


async def test_malformed_entries_are_filtered(log_agent):
    """A batch containing junk must not crash the pipeline."""
    logs = [
        {"id": "1", "message": "normal log", "source": "sshd"},
        {},
        {"message": None},
        {"parsed_fields": None},
    ]
    result = await log_agent.run({"logs": logs + [None, "string"]})
    assert "anomalies" in result


async def test_malformed_llm_output_degrades_to_pattern_hits(fake_cache):
    agent = build_agent("total gibberish, no json")
    logs = [make_brute_force_log() for _ in range(3)]
    result = await agent.run({"logs": logs})
    assert result["anomalies"] == []
    assert "brute_force" in result["pattern_hits"]
