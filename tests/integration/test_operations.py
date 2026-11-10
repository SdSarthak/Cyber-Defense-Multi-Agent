"""Write access, containment approval, durable escalations and the simulator feed."""
from datetime import datetime, timedelta, timezone

import pytest

from api.middleware.auth import create_access_token
from core.config import settings


def _analyst() -> dict:
    return {"Authorization": f"Bearer {create_access_token('analyst', role='analyst')}"}


WRITE_ROUTES = [
    ("/api/v1/threats/analyze", {"message": "x"}),
    ("/api/v1/threats/batch-analyze", [{"message": "x"}]),
    ("/api/v1/incidents/respond", {"title": "x"}),
    ("/api/v1/incidents/abc/update", {"status": "resolved"}),
    ("/api/v1/incidents/abc/actions/0/approve", None),
    ("/api/v1/vulnerabilities/scan", {"asset_ips": ["10.0.0.1"]}),
    ("/api/v1/compliance/evaluate", {"framework": "SOC2"}),
    ("/api/v1/reports/generate", {"report_type": "executive"}),
    ("/api/v1/agents/run", {"agent": "threat_detection", "payload": {}}),
]


# ── Analysts are read-only ────────────────────────────────────────────────────

@pytest.mark.parametrize("path,body", WRITE_ROUTES)
async def test_analyst_cannot_call_write_routes(api_client, mock_supervisor, path, body):
    resp = await api_client.post(path, json=body, headers=_analyst())
    assert resp.status_code == 403
    assert "read-only" in resp.json()["detail"]
    mock_supervisor._run_agent.assert_not_awaited()


async def test_analyst_keeps_read_access(api_client):
    resp = await api_client.get("/api/v1/incidents/", headers=_analyst())
    assert resp.status_code == 200


async def test_write_rate_limit(api_client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "api_write_rate_limit_per_minute", 2)
    codes = [
        (await api_client.post("/api/v1/threats/analyze", json={"message": "x"}, headers=auth_headers)).status_code
        for _ in range(3)
    ]
    assert codes == [200, 200, 429]


# ── Containment approval ──────────────────────────────────────────────────────

@pytest.fixture
async def pending_incident(fake_cache):
    await fake_cache.set("incident:inc-1", {
        "incident_id": "inc-1", "title": "Brute force",
        "response_plan": {"containment_actions": [
            {"action": "Block source IP", "automated": True, "status": "pending_approval"},
            {"action": "Notify team", "automated": False, "status": "pending"},
        ]},
    })
    return "inc-1"


async def test_admin_approves_a_pending_action(api_client, auth_headers, fake_cache, pending_incident):
    resp = await api_client.post(f"/api/v1/incidents/{pending_incident}/actions/0/approve", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    # No integration configured: recorded as simulated, never as completed.
    assert body["action"]["status"] == "simulated"
    stored = fake_cache.store["incident:inc-1"]["response_plan"]["containment_actions"][0]
    assert stored["status"] == "simulated"
    assert fake_cache.messages_on("incident_updates")[-1]["action_status"] == "simulated"

    again = await api_client.post(f"/api/v1/incidents/{pending_incident}/actions/0/approve", headers=auth_headers)
    assert again.status_code == 409


async def test_manual_actions_cannot_be_approved(api_client, auth_headers, pending_incident):
    resp = await api_client.post(f"/api/v1/incidents/{pending_incident}/actions/1/approve", headers=auth_headers)
    assert resp.status_code == 409


async def test_admin_rejects_a_pending_action(api_client, auth_headers, fake_cache, pending_incident):
    resp = await api_client.post(f"/api/v1/incidents/{pending_incident}/actions/0/reject", headers=auth_headers)
    assert resp.json()["action"]["status"] == "rejected"


@pytest.mark.parametrize("path", [
    "/api/v1/incidents/missing/actions/0/approve", "/api/v1/incidents/inc-1/actions/9/approve",
])
async def test_unknown_incident_or_action_is_404(api_client, auth_headers, pending_incident, path):
    assert (await api_client.post(path, headers=auth_headers)).status_code == 404


# ── Read paths ────────────────────────────────────────────────────────────────

async def test_report_list_hides_expired_reports(api_client, auth_headers, fake_cache):
    await fake_cache.lpush("reports:index", {"key": "report:executive:old", "type": "executive", "ts": "x"})
    await fake_cache.lpush("reports:index", {"key": "report:executive:live", "type": "executive", "ts": "y"})
    await fake_cache.set("report:executive:live", {"executive_summary": "ok"})
    body = (await api_client.get("/api/v1/reports/", headers=auth_headers)).json()
    assert [r["key"] for r in body["reports"]] == ["report:executive:live"]


async def test_stale_disabled_status_is_not_reported_as_paused(api_client, auth_headers, fake_cache):
    await fake_cache.hset("agent_status:compliance", {"status": "disabled", "task_id": ""})
    body = (await api_client.get("/api/v1/agents/compliance/status", headers=auth_headers)).json()
    assert body == {"status": "idle", "task_id": "", "paused": False}


async def test_log_search_reports_unavailable_backend(api_client, auth_headers):
    body = (await api_client.get("/api/v1/logs/search?q=", headers=auth_headers)).json()
    assert body == {"logs": [], "count": 0, "source": "unavailable"}


async def test_log_search_returns_matches(api_client, auth_headers, monkeypatch):
    from core.database import es_client
    seen = {}

    async def fake_search(query, limit, anomalous_only):
        seen.update(query=query, limit=limit, anomalous_only=anomalous_only)
        return [{"message": "Failed password", "is_anomalous": True}]

    monkeypatch.setattr(es_client, "search_logs", fake_search)
    body = (await api_client.get(
        "/api/v1/logs/search?q=failed&anomalous_only=true&limit=5", headers=auth_headers
    )).json()
    assert body["source"] == "elasticsearch" and body["count"] == 1
    assert seen == {"query": "failed", "limit": 5, "anomalous_only": True}


# ── Durable escalations ───────────────────────────────────────────────────────

async def test_escalations_are_handled_then_acknowledged(fake_cache, mock_supervisor):
    from agents.base_agent import ESCALATION_STREAM
    from api.websocket.manager import ESCALATION_GROUP, process_escalations_once

    await fake_cache.xadd(ESCALATION_STREAM, {"agent": "log_analysis", "threat_type": "brute_force"})
    await fake_cache.xadd(ESCALATION_STREAM, {"agent": "log_analysis", "threat_type": "sql_injection"})
    assert await process_escalations_once(mock_supervisor, "c1") == 2
    assert mock_supervisor.handle_escalation.await_count == 2
    assert fake_cache.groups[(ESCALATION_STREAM, ESCALATION_GROUP)]["pending"] == {}


async def test_a_failing_escalation_does_not_wedge_the_queue(fake_cache, mock_supervisor):
    from agents.base_agent import ESCALATION_STREAM
    from api.websocket.manager import ESCALATION_GROUP, process_escalations_once

    mock_supervisor.handle_escalation.side_effect = RuntimeError("boom")
    await fake_cache.xadd(ESCALATION_STREAM, {"agent": "x"})
    await process_escalations_once(mock_supervisor, "c1")
    assert fake_cache.groups[(ESCALATION_STREAM, ESCALATION_GROUP)]["pending"] == {}


# ── Simulator feed ────────────────────────────────────────────────────────────

async def test_drain_drops_and_counts_stale_logs(fake_cache):
    from api.main import SIM_QUEUE_KEY, drain_sim_queue
    from core import metrics
    now = datetime.now(timezone.utc)
    old = (now - timedelta(hours=2)).isoformat()
    await fake_cache.lpush(SIM_QUEUE_KEY, {"message": "old-1", "timestamp": old})
    await fake_cache.lpush(SIM_QUEUE_KEY, {"message": "old-2", "timestamp": old})
    await fake_cache.lpush(SIM_QUEUE_KEY, {"message": "fresh", "timestamp": now.isoformat()})
    await fake_cache.lpush(SIM_QUEUE_KEY, {"message": "untimed"})
    before = metrics.simulation_logs_dropped_total._value.get()

    fresh, dropped = await drain_sim_queue(batch_size=10, max_lag_seconds=600)
    assert [e["message"] for e in fresh] == ["fresh", "untimed"]
    assert dropped == 2
    assert metrics.simulation_logs_dropped_total._value.get() - before == 2


async def test_injected_attack_becomes_an_incident_through_detection_alone(fake_cache, monkeypatch):
    """
    End to end with the simulator's escalation shortcut off: the queued brute-force
    campaign must be caught by log analysis, escalated, and turned into an incident.
    """
    from api.main import drain_sim_queue
    from api.websocket.manager import process_escalations_once
    from agents.supervisor.agent import SupervisorAgent
    from simulation.engine import SimulationEngine
    from tests.conftest import patch_llm, CANNED_RESPONSES

    await SimulationEngine()._inject_brute_force_campaign()
    assert fake_cache.messages_on("escalations") == []

    with patch_llm({**CANNED_RESPONSES["log"], "anomalies": []}):
        supervisor = SupervisorAgent()
        batch, _ = await drain_sim_queue(batch_size=100, max_lag_seconds=600)
        await supervisor._agents["log_analysis"]._run_with_telemetry({"logs": batch})
    with patch_llm(CANNED_RESPONSES["incident"]):
        supervisor._agents["incident_response"]._llm = None
        handled = await process_escalations_once(supervisor, "c1")

    assert handled == 1
    incidents = await fake_cache.lrange("incidents:index", 0, -1)
    assert len(incidents) == 1
    record = await fake_cache.get(f"incident:{incidents[0]['incident_id']}")
    assert record["playbook"] == "brute_force"
    assert fake_cache.store["blackboard:threat_level"] == "high"
