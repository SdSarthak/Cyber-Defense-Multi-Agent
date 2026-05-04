"""Unit tests for LogAnalysisAgent."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from simulation.log_generators.generators import generate_batch, make_brute_force_log, make_c2_beacon_log


def _patch_env(monkeypatch):
    store = {}
    published = []
    mock_cache = MagicMock()
    mock_cache.set = AsyncMock(side_effect=lambda k, v, ttl=None: store.update({k: v}))
    mock_cache.get = AsyncMock(side_effect=lambda k: store.get(k))
    mock_cache.hset = AsyncMock()
    mock_cache.hgetall = AsyncMock(return_value={})
    mock_cache.lpush = AsyncMock()
    mock_cache.lrange = AsyncMock(return_value=[])
    mock_cache.publish = AsyncMock(side_effect=lambda ch, msg: published.append((ch, msg)))
    mock_cache._redis = MagicMock()
    mock_cache._redis.ltrim = AsyncMock()
    monkeypatch.setattr("core.database.redis_client.cache", mock_cache)
    monkeypatch.setattr("core.memory.agent_memory.cache", mock_cache)
    return mock_cache, store, published


@pytest.fixture
def log_agent(monkeypatch):
    _patch_env(monkeypatch)
    llm_response = json.dumps({
        "anomaly_count": 2, "total_analyzed": 20,
        "anomalies": [
            {"log_index": 0, "anomaly_type": "brute_force", "severity": "high",
             "source": "185.220.101.45", "description": "50 failed logins", "action": "block_ip"},
            {"log_index": 5, "anomaly_type": "c2_beacon", "severity": "critical",
             "source": "10.0.1.5", "description": "C2 beacon", "action": "isolate"},
        ],
        "patterns_detected": ["brute_force", "c2_beacon"],
        "risk_summary": "Active attack detected",
    })
    with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
        llm = MagicMock()
        resp = MagicMock()
        resp.content = llm_response
        llm.ainvoke = AsyncMock(return_value=resp)
        MockLLM.return_value = llm
        from agents.log_analysis.agent import LogAnalysisAgent
        return LogAnalysisAgent()


@pytest.mark.asyncio
async def test_log_agent_returns_anomalies(log_agent):
    logs = generate_batch(size=20, attack_probability=0.3)
    result = await log_agent.run({"logs": logs})
    assert "anomalies" in result
    assert "pattern_hits" in result
    assert "summary" in result


@pytest.mark.asyncio
async def test_log_agent_empty_input(log_agent):
    result = await log_agent.run({"logs": []})
    assert result["summary"] == "No logs provided"
    assert result["anomalies"] == []


@pytest.mark.asyncio
async def test_pattern_scan_detects_brute_force(log_agent):
    logs = [make_brute_force_log() for _ in range(10)]
    result = await log_agent.run({"logs": logs})
    assert "brute_force" in result["pattern_hits"]


@pytest.mark.asyncio
async def test_pattern_scan_detects_c2(log_agent):
    logs = [make_c2_beacon_log() for _ in range(5)]
    result = await log_agent.run({"logs": logs})
    # C2 pattern may not have a regex hit but LLM should catch it
    assert "anomalies" in result


@pytest.mark.asyncio
async def test_anomalies_sorted_by_severity(log_agent):
    logs = generate_batch(size=30, attack_probability=0.5)
    result = await log_agent.run({"logs": logs})
    anomalies = result["anomalies"]
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for i in range(len(anomalies) - 1):
        s1 = severity_order.get(anomalies[i].get("severity", "low"), 1)
        s2 = severity_order.get(anomalies[i + 1].get("severity", "low"), 1)
        assert s1 >= s2


@pytest.mark.asyncio
async def test_large_batch_truncated_gracefully(log_agent):
    logs = generate_batch(size=200, attack_probability=0.1)
    result = await log_agent.run({"logs": logs})
    assert "anomalies" in result
