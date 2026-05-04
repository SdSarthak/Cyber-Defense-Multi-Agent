"""Integration tests for FastAPI endpoints using HTTPX test client."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_supervisor():
    sup = MagicMock()
    sup._run_with_telemetry = AsyncMock(return_value={
        "summary": "Test run complete",
        "final_report": {"threat_level": "low"},
        "agent_results": {},
        "routing_decision": {"agents": ["threat_detection"]},
    })
    sup._run_agent = AsyncMock(return_value={
        "summary": "Agent ran ok",
        "threat_assessment": {"threat_type": "port_scan", "severity": "medium", "confidence": 0.7},
        "severity": "medium",
        "should_escalate": False,
        "anomalies": [],
        "risk_reports": [],
        "response_plan": {"priority": "p2", "containment_actions": []},
        "playbook_name": "default",
        "control_results": [],
        "overall_score": 75.0,
        "failed_controls": [],
        "report": {"executive_summary": "All good"},
    })
    return sup


@pytest.fixture
def mock_cache():
    cache = MagicMock()
    cache.hgetall = AsyncMock(return_value={})
    cache.lrange = AsyncMock(return_value=[])
    cache.get = AsyncMock(return_value=None)
    cache.set = AsyncMock()
    cache.publish = AsyncMock()
    return cache


@pytest.mark.asyncio
async def test_health_endpoint(mock_supervisor, mock_cache, monkeypatch):
    monkeypatch.setattr("core.database.redis_client.cache", mock_cache)
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()
    monkeypatch.setattr("core.database.redis_client.get_redis", lambda: mock_redis)

    with patch("api.main._create_supervisor", return_value=mock_supervisor), \
         patch("api.main.init_db", new_callable=AsyncMock):
        from httpx import AsyncClient, ASGITransport
        from api.main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_analyze_threat_endpoint(mock_supervisor, mock_cache, monkeypatch):
    monkeypatch.setattr("core.database.redis_client.cache", mock_cache)
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()
    monkeypatch.setattr("core.database.redis_client.get_redis", lambda: mock_redis)

    with patch("api.main._create_supervisor", return_value=mock_supervisor), \
         patch("api.main.init_db", new_callable=AsyncMock):
        from httpx import AsyncClient, ASGITransport
        from api.main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/v1/threats/analyze", json={
                "source_ip": "1.2.3.4",
                "message": "port scan detected",
            })
    assert resp.status_code == 200
    data = resp.json()
    assert "severity" in data or "summary" in data


@pytest.mark.asyncio
async def test_agent_statuses_endpoint(mock_supervisor, mock_cache, monkeypatch):
    monkeypatch.setattr("core.database.redis_client.cache", mock_cache)
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()
    monkeypatch.setattr("core.database.redis_client.get_redis", lambda: mock_redis)

    with patch("api.main._create_supervisor", return_value=mock_supervisor), \
         patch("api.main.init_db", new_callable=AsyncMock):
        from httpx import AsyncClient, ASGITransport
        from api.main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/v1/agents/status")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)


@pytest.mark.asyncio
async def test_compliance_list_frameworks(mock_supervisor, mock_cache, monkeypatch):
    monkeypatch.setattr("core.database.redis_client.cache", mock_cache)
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()
    monkeypatch.setattr("core.database.redis_client.get_redis", lambda: mock_redis)

    with patch("api.main._create_supervisor", return_value=mock_supervisor), \
         patch("api.main.init_db", new_callable=AsyncMock):
        from httpx import AsyncClient, ASGITransport
        from api.main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/v1/compliance/frameworks")
    assert resp.status_code == 200
    assert "frameworks" in resp.json()
    assert "SOC2" in resp.json()["frameworks"]


@pytest.mark.asyncio
async def test_run_agent_unknown_returns_400(mock_supervisor, mock_cache, monkeypatch):
    monkeypatch.setattr("core.database.redis_client.cache", mock_cache)
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()
    monkeypatch.setattr("core.database.redis_client.get_redis", lambda: mock_redis)

    with patch("api.main._create_supervisor", return_value=mock_supervisor), \
         patch("api.main.init_db", new_callable=AsyncMock):
        from httpx import AsyncClient, ASGITransport
        from api.main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/v1/agents/run", json={"agent": "does_not_exist", "payload": {}})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_incident_not_found_returns_404(mock_supervisor, mock_cache, monkeypatch):
    monkeypatch.setattr("core.database.redis_client.cache", mock_cache)
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()
    monkeypatch.setattr("core.database.redis_client.get_redis", lambda: mock_redis)

    with patch("api.main._create_supervisor", return_value=mock_supervisor), \
         patch("api.main.init_db", new_callable=AsyncMock):
        from httpx import AsyncClient, ASGITransport
        from api.main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/v1/incidents/nonexistent-id")
    assert resp.status_code == 404
