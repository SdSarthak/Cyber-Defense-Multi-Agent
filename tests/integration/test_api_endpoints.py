"""Integration tests for FastAPI endpoints using the HTTPX ASGI transport."""
import pytest


# ── Health / metrics (unauthenticated) ────────────────────────────────────────

async def test_health_endpoint(api_client):
    resp = await api_client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_readiness_reports_every_backend(api_client):
    resp = await api_client.get("/health/ready")
    assert resp.status_code in (200, 503)
    checks = resp.json()["checks"]
    assert set(checks) == {"redis", "postgres", "elasticsearch", "chromadb"}


async def test_metrics_endpoint_exposes_dashboard_series(api_client):
    await api_client.get("/health")
    resp = await api_client.get("/metrics")
    assert resp.status_code == 200
    body = resp.text
    # These are exactly the series the provisioned Grafana dashboard queries.
    assert "http_requests_total" in body
    assert "http_request_duration_seconds" in body
    assert "websocket_connections_active" in body


# ── Authentication ────────────────────────────────────────────────────────────

async def test_protected_route_requires_token(api_client):
    resp = await api_client.get("/api/v1/agents/status")
    assert resp.status_code == 401


async def test_protected_route_rejects_garbage_token(api_client):
    resp = await api_client.get(
        "/api/v1/agents/status", headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert resp.status_code == 401


async def test_login_returns_token(api_client):
    resp = await api_client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin123"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "admin"
    assert body["access_token"]


async def test_login_rejects_bad_password(api_client):
    resp = await api_client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "wrong"}
    )
    assert resp.status_code == 401


async def test_login_token_opens_protected_route(api_client):
    login = await api_client.post(
        "/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"}
    )
    token = login.json()["access_token"]
    resp = await api_client.get(
        "/api/v1/agents/status", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200


async def test_me_returns_identity(api_client, auth_headers):
    resp = await api_client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"


# ── Agents ────────────────────────────────────────────────────────────────────

async def test_agent_statuses_endpoint(api_client, auth_headers):
    resp = await api_client.get("/api/v1/agents/status", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "threat_detection" in body
    assert body["threat_detection"]["paused"] is False


async def test_run_agent_unknown_returns_400(api_client, auth_headers):
    resp = await api_client.post(
        "/api/v1/agents/run", json={"agent": "does_not_exist", "payload": {}},
        headers=auth_headers,
    )
    assert resp.status_code == 400


async def test_run_agent_dispatches_to_supervisor(api_client, auth_headers, mock_supervisor):
    resp = await api_client.post(
        "/api/v1/agents/run",
        json={"agent": "threat_detection", "payload": {"message": "port scan"}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    mock_supervisor._run_agent.assert_awaited()


async def test_pause_and_resume_agent(api_client, auth_headers, fake_cache):
    paused = await api_client.post(
        "/api/v1/agents/threat_detection/pause", headers=auth_headers
    )
    assert paused.status_code == 200

    status = await api_client.get("/api/v1/agents/status", headers=auth_headers)
    assert status.json()["threat_detection"]["paused"] is True

    resumed = await api_client.post(
        "/api/v1/agents/threat_detection/resume", headers=auth_headers
    )
    assert resumed.status_code == 200
    status = await api_client.get("/api/v1/agents/status", headers=auth_headers)
    assert status.json()["threat_detection"]["paused"] is False


async def test_pause_unknown_agent_returns_404(api_client, auth_headers):
    resp = await api_client.post("/api/v1/agents/nope/pause", headers=auth_headers)
    assert resp.status_code == 404


async def test_agent_history_endpoint(api_client, auth_headers, fake_cache):
    await fake_cache.lpush("agent:threat_detection:history", {"type": "task_complete"})
    resp = await api_client.get(
        "/api/v1/agents/threat_detection/history", headers=auth_headers
    )
    assert resp.status_code == 200
    assert len(resp.json()["history"]) == 1


# ── Threats ───────────────────────────────────────────────────────────────────

async def test_analyze_threat_endpoint(api_client, auth_headers):
    resp = await api_client.post(
        "/api/v1/threats/analyze",
        json={"source_ip": "1.2.3.4", "message": "port scan detected"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "severity" in resp.json()


async def test_batch_analyze_rejects_oversized_batch(api_client, auth_headers):
    events = [{"message": f"event {i}"} for i in range(25)]
    resp = await api_client.post(
        "/api/v1/threats/batch-analyze", json=events, headers=auth_headers
    )
    assert resp.status_code == 400


async def test_batch_analyze_rejects_empty_batch(api_client, auth_headers):
    resp = await api_client.post(
        "/api/v1/threats/batch-analyze", json=[], headers=auth_headers
    )
    assert resp.status_code == 400


async def test_recent_threats_falls_back_to_redis(api_client, auth_headers, fake_cache):
    await fake_cache.lpush("agent:threat_detection:history", {"type": "task_complete"})
    resp = await api_client.get("/api/v1/threats/recent", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "redis"
    assert body["count"] == 1


# ── Incidents ─────────────────────────────────────────────────────────────────

async def test_incident_not_found_returns_404(api_client, auth_headers):
    resp = await api_client.get("/api/v1/incidents/nonexistent-id", headers=auth_headers)
    assert resp.status_code == 404


async def test_incident_found_in_redis(api_client, auth_headers, fake_cache):
    await fake_cache.set("incident:abc", {"status": "investigating"})
    resp = await api_client.get("/api/v1/incidents/abc", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


async def test_incident_update_rejects_invalid_status(api_client, auth_headers, fake_cache):
    await fake_cache.set("incident:abc", {"status": "open"})
    resp = await api_client.post(
        "/api/v1/incidents/abc/update", json={"status": "banana"}, headers=auth_headers
    )
    assert resp.status_code == 400


async def test_incident_update_applies_status(api_client, auth_headers, fake_cache):
    await fake_cache.set("incident:abc", {"status": "open"})
    resp = await api_client.post(
        "/api/v1/incidents/abc/update",
        json={"status": "contained", "notes": "isolated host"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    stored = await fake_cache.get("incident:abc")
    assert stored["status"] == "contained"
    assert "isolated host" in stored["notes"]


# ── Vulnerabilities ───────────────────────────────────────────────────────────

async def test_vuln_scan_requires_input(api_client, auth_headers):
    resp = await api_client.post(
        "/api/v1/vulnerabilities/scan", json={"cve_ids": [], "asset_ips": []},
        headers=auth_headers,
    )
    assert resp.status_code == 400


async def test_vuln_scan_rejects_malformed_cve(api_client, auth_headers):
    resp = await api_client.post(
        "/api/v1/vulnerabilities/scan", json={"cve_ids": ["not-a-cve"]},
        headers=auth_headers,
    )
    assert resp.status_code == 400


async def test_cve_lookup_rejects_malformed_id(api_client, auth_headers):
    resp = await api_client.get("/api/v1/vulnerabilities/cve/abc123", headers=auth_headers)
    assert resp.status_code == 400


# ── Compliance ────────────────────────────────────────────────────────────────

async def test_compliance_list_frameworks(api_client, auth_headers):
    resp = await api_client.get("/api/v1/compliance/frameworks", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "SOC2" in body["frameworks"]
    assert body["controls"]["SOC2"] > 0


async def test_compliance_framework_controls(api_client, auth_headers):
    resp = await api_client.get("/api/v1/compliance/frameworks/SOC2", headers=auth_headers)
    assert resp.status_code == 200
    assert "CC6.1" in resp.json()["controls"]


async def test_compliance_unknown_framework_returns_404(api_client, auth_headers):
    resp = await api_client.get("/api/v1/compliance/frameworks/HIPAA", headers=auth_headers)
    assert resp.status_code == 404


async def test_compliance_evaluate_rejects_unsupported(api_client, auth_headers):
    resp = await api_client.post(
        "/api/v1/compliance/evaluate", json={"framework": "HIPAA"}, headers=auth_headers
    )
    assert resp.status_code == 400


# ── Reports ───────────────────────────────────────────────────────────────────

async def test_report_generate_rejects_unknown_type(api_client, auth_headers):
    resp = await api_client.post(
        "/api/v1/reports/generate", json={"report_type": "haiku"}, headers=auth_headers
    )
    assert resp.status_code == 400


async def test_report_key_traversal_is_blocked(api_client, auth_headers, fake_cache):
    """A report key must be scoped to report:* so this endpoint cannot read agent state."""
    await fake_cache.set("blackboard:threat_level", "critical")
    resp = await api_client.get(
        "/api/v1/reports/blackboard:threat_level", headers=auth_headers
    )
    assert resp.status_code == 400


async def test_report_fetch_returns_stored_report(api_client, auth_headers, fake_cache):
    await fake_cache.set("report:executive:20260101_000000", {"executive_summary": "ok"})
    resp = await api_client.get(
        "/api/v1/reports/report:executive:20260101_000000", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json()["executive_summary"] == "ok"


# ── Supervisor unavailable ────────────────────────────────────────────────────

async def test_routes_return_503_without_supervisor(auth_headers):
    from httpx import ASGITransport, AsyncClient
    from api.main import app

    if hasattr(app.state, "supervisor"):
        del app.state._state["supervisor"]
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/threats/analyze", json={"message": "x"}, headers=auth_headers
            )
        assert resp.status_code == 503
    finally:
        app.state.supervisor = None
        del app.state._state["supervisor"]
