"""Unit tests for IncidentResponseAgent."""
import pytest

from agents.incident_response.agent import PLAYBOOKS
from tests.conftest import patch_llm

IR_PLAN = {
    "incident_id": "0d1b6d1e-1f5f-4a1a-9c62-2c9f3b6d5e77",
    "playbook": "brute_force", "priority": "p1",
    "containment_actions": [
        {"action": "Block source IP at firewall", "automated": True, "status": "pending"},
        {"action": "Reset compromised credentials", "automated": False, "status": "pending"},
    ],
    "investigation_steps": ["Review auth logs", "Check other hosts"],
    "communication_plan": {"internal": "Notify SOC", "external": ""},
    "timeline": [{"time": "T+0", "event": "Detection"}],
    "estimated_resolution": "2h",
    "lessons_learned": ["Enforce MFA"],
}


def build_agent(response=IR_PLAN):
    from agents.incident_response.agent import IncidentResponseAgent
    agent = IncidentResponseAgent()
    with patch_llm(response):
        _ = agent.llm
    return agent


@pytest.fixture
def ir_agent(fake_cache):
    return build_agent()


async def test_ir_agent_basic_response(ir_agent):
    result = await ir_agent.run({
        "incident": {"title": "Brute force on SSH", "type": "brute_force"},
        "threat_assessment": {"threat_type": "brute_force", "severity": "high"},
    })
    assert result["playbook_name"] == "brute_force"
    assert result["response_plan"]["priority"] == "p1"
    assert "summary" in result


@pytest.mark.parametrize("threat_type,expected", [
    ("brute_force", "brute_force"),
    ("ransomware", "ransomware"),
    ("data_exfiltration", "data_exfiltration"),
    ("c2_beacon", "c2_beacon"),
    ("sql_injection", "sql_injection"),
    ("unknown_threat", "default"),
])
async def test_playbook_selection(ir_agent, threat_type, expected):
    result = await ir_agent.run({
        "incident": {"type": threat_type},
        "threat_assessment": {"threat_type": threat_type},
    })
    assert result["playbook_name"] == expected


async def test_playbook_falls_back_to_incident_type(ir_agent):
    """With no threat assessment the incident's own type must still pick a playbook."""
    result = await ir_agent.run({
        "incident": {"type": "ransomware"},
        "threat_assessment": {},
    })
    assert result["playbook_name"] == "ransomware"


async def test_automated_actions_executed(ir_agent):
    result = await ir_agent.run({
        "incident": {"title": "Test"},
        "threat_assessment": {"threat_type": "brute_force"},
    })
    automated = result["actions_taken"]
    assert automated, "expected at least one automated containment action"
    assert all(a["status"] == "completed" for a in automated)
    # Manual steps are left for a human and must not be marked done.
    manual = [
        a for a in result["response_plan"]["containment_actions"] if not a.get("automated")
    ]
    assert all(a["status"] == "pending" for a in manual)


async def test_incident_stored_in_redis(ir_agent, fake_cache):
    result = await ir_agent.run({
        "incident": {"title": "Test"},
        "threat_assessment": {},
    })
    incident_id = result["incident_id"]
    stored = await fake_cache.get(f"incident:{incident_id}")
    assert stored["status"] == "investigating"
    assert await fake_cache.llen("incidents:index") == 1


async def test_incident_update_published(ir_agent, fake_cache):
    await ir_agent.run({"incident": {"title": "Test"}, "threat_assessment": {}})
    updates = fake_cache.messages_on("incident_updates")
    assert len(updates) == 1
    assert updates[0]["agent"] == "incident_response"


async def test_malformed_llm_response_uses_playbook_steps(fake_cache):
    """When the model returns junk the agent must still emit the canned playbook."""
    agent = build_agent("not json at all")
    result = await agent.run({
        "incident": {"title": "Test"},
        "threat_assessment": {"threat_type": "ransomware"},
    })
    actions = [a["action"] for a in result["response_plan"]["containment_actions"]]
    assert actions == PLAYBOOKS["ransomware"]
    assert result["response_plan"]["priority"] == "p2"


async def test_plan_without_containment_actions_is_backfilled(fake_cache):
    agent = build_agent({"playbook": "brute_force", "priority": "p3"})
    result = await agent.run({
        "incident": {"title": "Test"},
        "threat_assessment": {"threat_type": "brute_force"},
    })
    assert result["response_plan"]["containment_actions"]
    assert result["response_plan"]["incident_id"]


async def test_non_dict_incident_is_tolerated(ir_agent):
    result = await ir_agent.run({"incident": "just a string", "threat_assessment": {}})
    assert "response_plan" in result
