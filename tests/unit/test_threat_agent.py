"""Unit tests for ThreatDetectionAgent."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def _make_mock_llm(response_json: dict):
    mock = MagicMock()
    result = MagicMock()
    result.content = json.dumps(response_json)
    mock.ainvoke = AsyncMock(return_value=result)
    return mock


@pytest.fixture
def mock_deps(monkeypatch):
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
def threat_agent(mock_deps, monkeypatch):
    monkeypatch.setattr("core.rag.rag_chain.threat_rag", AsyncMock(return_value="threat context"))
    monkeypatch.setattr("core.tools.threat_tools.enrich_ip",
                        AsyncMock(return_value=json.dumps({"ip": "185.220.101.45", "risk_score": 80})))
    monkeypatch.setattr("core.tools.threat_tools.score_ioc",
                        AsyncMock(return_value=json.dumps({"ioc": "185.220.101.45", "risk_score": 60})))
    with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
        llm_instance = _make_mock_llm({
            "threat_type": "port_scan", "severity": "high", "confidence": 0.9,
            "indicators": ["185.220.101.45"], "mitre_tactics": ["Reconnaissance"],
            "mitre_techniques": ["T1046"], "reasoning": "Port scan detected",
            "should_escalate": True,
        })
        MockLLM.return_value = llm_instance
        from agents.threat_detection.agent import ThreatDetectionAgent
        return ThreatDetectionAgent()


@pytest.mark.asyncio
async def test_threat_agent_returns_assessment(threat_agent):
    result = await threat_agent.run({
        "source_ip": "185.220.101.45",
        "destination_ip": "10.0.1.50",
        "message": "Port scan from 185.220.101.45",
    })
    assert "threat_assessment" in result
    assert "severity" in result
    assert "summary" in result


@pytest.mark.asyncio
async def test_threat_agent_escalates_high_severity(threat_agent, mock_deps):
    _, _, published = mock_deps
    await threat_agent.run({"source_ip": "185.220.101.45", "message": "Critical threat"})
    escalations = [p for ch, p in published if ch == "escalations"]
    assert len(escalations) >= 1


@pytest.mark.asyncio
async def test_threat_agent_handles_empty_event(threat_agent):
    result = await threat_agent.run({})
    assert "threat_assessment" in result


@pytest.mark.asyncio
async def test_threat_agent_handles_malformed_llm_json(mock_deps, monkeypatch):
    monkeypatch.setattr("core.rag.rag_chain.threat_rag", AsyncMock(return_value=""))
    with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
        bad_llm = MagicMock()
        bad_result = MagicMock()
        bad_result.content = "NOT JSON AT ALL {broken"
        bad_llm.ainvoke = AsyncMock(return_value=bad_result)
        MockLLM.return_value = bad_llm
        from agents.threat_detection.agent import ThreatDetectionAgent
        agent = ThreatDetectionAgent()
        result = await agent.run({"message": "test"})
    assert result["threat_assessment"]["threat_type"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("severity,should_escalate", [
    ("critical", True),
    ("high", True),
    ("medium", False),
    ("low", False),
])
async def test_escalation_by_severity(severity, should_escalate, mock_deps, monkeypatch):
    monkeypatch.setattr("core.rag.rag_chain.threat_rag", AsyncMock(return_value=""))
    with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
        llm = _make_mock_llm({
            "threat_type": "test", "severity": severity, "confidence": 0.8,
            "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
            "reasoning": "test", "should_escalate": False,
        })
        MockLLM.return_value = llm
        from agents.threat_detection.agent import ThreatDetectionAgent
        agent = ThreatDetectionAgent()
        result = await agent.run({"message": "test"})
    assert result["should_escalate"] == should_escalate
