import asyncio
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport
from core.config import settings


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_redis(monkeypatch):
    """Patch Redis cache with a fast in-memory mock."""
    store = {}
    lists = {}
    published = []

    mock = MagicMock()
    mock.set = AsyncMock(side_effect=lambda k, v, ttl=None: store.update({k: v}))
    mock.get = AsyncMock(side_effect=lambda k: store.get(k))
    mock.delete = AsyncMock(side_effect=lambda k: store.pop(k, None))
    mock.exists = AsyncMock(side_effect=lambda k: k in store)
    mock.publish = AsyncMock(side_effect=lambda ch, msg: published.append((ch, msg)))
    mock.lpush = AsyncMock(side_effect=lambda k, v: lists.setdefault(k, []).insert(0, v))
    mock.lrange = AsyncMock(side_effect=lambda k, s, e: (lists.get(k, [])[s:None if e == -1 else e + 1]))
    mock.hset = AsyncMock()
    mock.hgetall = AsyncMock(return_value={})
    mock.incr = AsyncMock(return_value=1)
    mock._redis = MagicMock()
    mock._redis.ltrim = AsyncMock()

    monkeypatch.setattr("core.database.redis_client.cache", mock)
    return mock, store, published


@pytest.fixture
def mock_llm():
    """Patch Gemini LLM to return canned JSON for all agents."""
    import json
    responses = {
        "threat": json.dumps({
            "threat_type": "port_scan", "severity": "high", "confidence": 0.9,
            "indicators": ["185.220.101.45"], "mitre_tactics": ["Reconnaissance"],
            "mitre_techniques": ["T1046"], "reasoning": "Sequential port scan detected",
            "should_escalate": True,
        }),
        "log": json.dumps({
            "anomaly_count": 3, "total_analyzed": 10,
            "anomalies": [
                {"log_index": 0, "anomaly_type": "brute_force", "severity": "high",
                 "source": "185.220.101.45", "description": "50 failed logins", "action": "block_ip"},
            ],
            "patterns_detected": ["brute_force"], "risk_summary": "Brute force detected",
        }),
        "vuln": json.dumps({
            "risk_score": 9.8, "exploitability": "high", "business_impact": "critical",
            "patch_urgency": "immediate", "remediation": "Apply patch immediately",
            "workaround": "Disable feature X", "affected_assets": ["10.0.1.1"],
            "summary": "Critical RCE vulnerability",
        }),
        "incident": json.dumps({
            "incident_id": "test-123", "playbook": "brute_force", "priority": "p1",
            "containment_actions": [{"action": "Block IP", "automated": True, "status": "pending"}],
            "investigation_steps": ["Review auth logs"], "communication_plan": {},
            "timeline": [], "estimated_resolution": "2h", "lessons_learned": [],
        }),
        "compliance": json.dumps({
            "status": "partial", "score": 65.0, "findings": ["MFA not enforced"],
            "evidence_quality": "moderate", "remediation": "Enable MFA",
            "risk_if_failed": "high",
        }),
        "report": json.dumps({
            "executive_summary": "Security posture is moderate with active threats.",
            "threat_landscape": {"current_threats": ["brute_force"], "trend": "stable"},
            "key_metrics": {"total_incidents": 5, "critical_incidents": 1,
                            "mean_time_to_detect_hours": 0.5, "mean_time_to_respond_hours": 1.2,
                            "vulnerabilities_open": 12, "compliance_score": 72.0},
            "top_risks": [], "recommended_actions": [], "compliance_status": {}, "period": "2026-05",
        }),
        "router": json.dumps({
            "agents": ["threat_detection"], "reasoning": "Single threat event",
            "priority": "high", "parallel": False,
        }),
    }

    async def fake_invoke(prompt_value, **kwargs):
        content = list(responses.values())[0]
        for key, val in responses.items():
            if any(key in str(m) for m in (prompt_value if isinstance(prompt_value, list) else [prompt_value])):
                content = val
                break
        result = MagicMock()
        result.content = content
        return result

    with patch("langchain_google_genai.ChatGoogleGenerativeAI.ainvoke", new=fake_invoke):
        yield responses


@pytest.fixture
def sample_log_batch():
    from simulation.log_generators.generators import generate_batch
    return generate_batch(size=20, attack_probability=0.2)


@pytest.fixture
def sample_threat_event():
    return {
        "source_ip": "185.220.101.45",
        "destination_ip": "10.0.1.50",
        "source_port": 54321,
        "destination_port": 22,
        "protocol": "TCP",
        "message": "Failed password for root from 185.220.101.45 port 54321 ssh2",
        "raw": "sshd[1234]: Failed password for root from 185.220.101.45 port 54321 ssh2",
    }


@pytest.fixture
async def api_client():
    from api.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
