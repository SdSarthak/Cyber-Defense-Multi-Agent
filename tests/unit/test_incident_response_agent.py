"""Unit tests for IncidentResponseAgent."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def _make_ir_llm():
    resp = MagicMock()
    resp.content = json.dumps({
        "incident_id": "inc-001", "playbook": "brute_force", "priority": "p1",
        "containment_actions": [
            {"action": "Block source IP at firewall", "automated": True, "status": "pending"},
            {"action": "Reset compromised credentials", "automated": False, "status": "pending"},
        ],
        "investigation_steps": ["Review auth logs", "Check other hosts"],
        "communication_plan": {"internal": "Notify SOC", "external": ""},
        "timeline": [{"time": "T+0", "event": "Detection"}],
        "estimated_resolution": "2h",
        "lessons_learned": ["Enforce MFA"],
    })
    llm = MagicMock()
    llm.ainvoke = AsyncMock(return_value=resp)
    return llm


@pytest.fixture
def ir_agent(monkeypatch):
    mock_cache = MagicMock()
    mock_cache.set = AsyncMock()
    mock_cache.get = AsyncMock(return_value=None)
    mock_cache.hset = AsyncMock()
    mock_cache.hgetall = AsyncMock(return_value={})
    mock_cache.lpush = AsyncMock()
    mock_cache.lrange = AsyncMock(return_value=[])
    mock_cache.publish = AsyncMock()
    mock_cache._redis = MagicMock()
    mock_cache._redis.ltrim = AsyncMock()
    monkeypatch.setattr("core.database.redis_client.cache", mock_cache)
    monkeypatch.setattr("core.memory.agent_memory.cache", mock_cache)
    with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
        MockLLM.return_value = _make_ir_llm()
        from agents.incident_response.agent import IncidentResponseAgent
        return IncidentResponseAgent(), mock_cache


@pytest.mark.asyncio
async def test_ir_agent_basic_response(ir_agent):
    agent, _ = ir_agent
    result = await agent.run({
        "incident": {"title": "Brute force on SSH", "type": "brute_force"},
        "threat_assessment": {"threat_type": "brute_force", "severity": "high"},
    })
    assert "response_plan" in result
    assert "playbook_name" in result
    assert result["playbook_name"] == "brute_force"


@pytest.mark.asyncio
async def test_playbook_selection_brute_force(ir_agent):
    agent, _ = ir_agent
    result = await agent.run({
        "incident": {"type": "brute_force"},
        "threat_assessment": {"threat_type": "brute_force"},
    })
    assert result["playbook_name"] == "brute_force"


@pytest.mark.asyncio
async def test_playbook_selection_ransomware(ir_agent, monkeypatch):
    agent, _ = ir_agent
    result = await agent.run({
        "incident": {"type": "ransomware"},
        "threat_assessment": {"threat_type": "ransomware"},
    })
    assert result["playbook_name"] == "ransomware"


@pytest.mark.asyncio
async def test_playbook_selection_default(ir_agent):
    agent, _ = ir_agent
    result = await agent.run({
        "incident": {"type": "unknown_threat"},
        "threat_assessment": {},
    })
    assert result["playbook_name"] == "default"


@pytest.mark.asyncio
async def test_automated_actions_executed(ir_agent):
    agent, cache = ir_agent
    result = await agent.run({
        "incident": {"title": "Test"},
        "threat_assessment": {"threat_type": "brute_force"},
    })
    automated = [a for a in result.get("actions_taken", []) if a.get("automated")]
    for a in automated:
        assert a["status"] == "completed"


@pytest.mark.asyncio
async def test_incident_stored_in_redis(ir_agent):
    agent, cache = ir_agent
    await agent.run({
        "incident": {"id": "inc-001", "title": "Test"},
        "threat_assessment": {},
    })
    cache.set.assert_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("incident_type", [
    "brute_force", "ransomware", "data_exfiltration", "c2_beacon", "sql_injection", "unknown"
])
async def test_all_incident_types(ir_agent, incident_type):
    agent, _ = ir_agent
    result = await agent.run({
        "incident": {"type": incident_type, "title": f"{incident_type} incident"},
        "threat_assessment": {"threat_type": incident_type},
    })
    assert "response_plan" in result
    assert "summary" in result
