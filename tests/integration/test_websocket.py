"""WebSocket handshake auth, role enforcement and human-override round trips.

The socket accepts privileged commands (`pause_agent`, `run_agent`), so it is
authenticated exactly like the REST API. These tests pin that contract: an
unauthenticated handshake must be rejected *before* the socket is accepted, and an
analyst token must not be able to mutate agent state.
"""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from api.middleware.auth import create_access_token
from api.websocket.manager import (
    ADMIN_ONLY_COMMANDS,
    OVERRIDE_COMMANDS,
    WS_POLICY_VIOLATION,
)
from core.config import settings


@pytest.fixture
def client(mock_supervisor):
    """TestClient without lifespan — background listeners would need a real Redis."""
    from api.main import app
    app.state.supervisor = mock_supervisor
    return TestClient(app)


def _admin_token() -> str:
    return create_access_token("admin", role="admin")


def _analyst_token() -> str:
    return create_access_token("analyst", role="analyst")


def _override(ws, command: str, payload: dict) -> dict:
    ws.send_json({"type": "human_override", "command": command, "payload": payload})
    return ws.receive_json()


# ── Handshake ─────────────────────────────────────────────────────────────────

def test_connect_without_token_is_rejected(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()
    assert exc.value.code == WS_POLICY_VIOLATION


def test_connect_with_invalid_token_is_rejected(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws?token=not-a-jwt") as ws:
            ws.receive_json()
    assert exc.value.code == WS_POLICY_VIOLATION


def test_connect_with_valid_token_receives_hello(client):
    with client.websocket_connect(f"/ws?token={_admin_token()}") as ws:
        hello = ws.receive_json()
    assert hello["type"] == "connected"
    assert hello["user"] == "admin"
    assert hello["role"] == "admin"
    assert "agent_events" in hello["channels"]


def test_connect_accepts_authorization_header(client):
    headers = {"Authorization": f"Bearer {_admin_token()}"}
    with client.websocket_connect("/ws", headers=headers) as ws:
        hello = ws.receive_json()
    assert hello["role"] == "admin"


def test_anonymous_allowed_when_auth_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "websocket_auth_required", False)
    with client.websocket_connect("/ws") as ws:
        hello = ws.receive_json()
    assert hello["user"] == "anonymous"
    assert hello["role"] == "analyst"


# ── Authorisation ─────────────────────────────────────────────────────────────

def test_analyst_cannot_pause_an_agent(client):
    with client.websocket_connect(f"/ws?token={_analyst_token()}") as ws:
        ws.receive_json()
        reply = _override(ws, "pause_agent", {"agent": "threat_detection"})
    assert reply["result"]["ok"] is False
    assert "analyst" in reply["result"]["error"]


def test_admin_can_pause_and_resume(client, fake_cache):
    with client.websocket_connect(f"/ws?token={_admin_token()}") as ws:
        ws.receive_json()
        paused = _override(ws, "pause_agent", {"agent": "threat_detection"})
        resumed = _override(ws, "resume_agent", {"agent": "threat_detection"})

    assert paused["result"] == {"ok": True, "agent": "threat_detection", "status": "paused"}
    assert resumed["result"] == {"ok": True, "agent": "threat_detection", "status": "resumed"}


def test_analyst_may_set_threat_level(client, fake_cache):
    """set_threat_level is deliberately not admin-only — analysts run the board."""
    assert "set_threat_level" not in ADMIN_ONLY_COMMANDS
    with client.websocket_connect(f"/ws?token={_analyst_token()}") as ws:
        ws.receive_json()
        reply = _override(ws, "set_threat_level", {"threat_level": "high"})
    assert reply["result"] == {"ok": True, "threat_level": "high"}


# ── Command handling ──────────────────────────────────────────────────────────

def test_unknown_command_is_reported(client):
    with client.websocket_connect(f"/ws?token={_admin_token()}") as ws:
        ws.receive_json()
        reply = _override(ws, "self_destruct", {})
    assert reply["result"]["ok"] is False
    assert reply["result"]["supported"] == list(OVERRIDE_COMMANDS)


def test_malformed_json_is_reported(client):
    with client.websocket_connect(f"/ws?token={_admin_token()}") as ws:
        ws.receive_json()
        ws.send_text("{not json")
        reply = ws.receive_json()
    assert reply["type"] == "error"


def test_pause_agent_requires_agent_name(client):
    with client.websocket_connect(f"/ws?token={_admin_token()}") as ws:
        ws.receive_json()
        reply = _override(ws, "pause_agent", {})
    assert reply["result"]["ok"] is False


@pytest.mark.parametrize("command", ["run_agent", "pause_agent", "resume_agent"])
def test_agent_commands_reject_unknown_agent(client, command):
    """
    A typo must not silently succeed. `pause_agent` used to write a pause key for any
    string, so the operator was told an agent had stopped while it kept running.
    """
    with client.websocket_connect(f"/ws?token={_admin_token()}") as ws:
        ws.receive_json()
        reply = _override(ws, command, {"agent": "nope"})
    assert reply["result"]["ok"] is False
    assert "Unknown agent" in reply["result"]["error"]


def test_pause_agent_does_not_write_a_key_for_unknown_agent(client, fake_cache):
    with client.websocket_connect(f"/ws?token={_admin_token()}") as ws:
        ws.receive_json()
        _override(ws, "pause_agent", {"agent": "nope"})
    assert not [k for k in fake_cache.store if "nope" in k]


def test_override_is_audited_on_the_event_bus(client, fake_cache):
    with client.websocket_connect(f"/ws?token={_admin_token()}") as ws:
        ws.receive_json()
        _override(ws, "set_threat_level", {"threat_level": "critical"})

    events = fake_cache.messages_on("agent_events")
    assert events, "override should be published for the audit trail"
    assert events[-1]["user"] == "admin"
    assert events[-1]["command"] == "set_threat_level"
