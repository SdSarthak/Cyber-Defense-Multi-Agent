"""Telemetry wrapper behaviour shared by every agent."""
import asyncio

import pytest

from agents.base_agent import ESCALATION_STREAM, BaseSecurityAgent


class SlowAgent(BaseSecurityAgent):
    name = "slow_test"

    async def run(self, input_data: dict) -> dict:
        await asyncio.sleep(10)
        return {"summary": "never"}


class QuickAgent(BaseSecurityAgent):
    name = "quick_test"

    async def run(self, input_data: dict) -> dict:
        return {"summary": "done"}


def _events(fake_cache, agent):
    return [m["event"] for m in fake_cache.messages_on("agent_events") if m.get("agent") == agent]


async def test_cancelled_run_does_not_stay_running(fake_cache):
    """CancelledError skipped every handler, leaving the status 'running' forever."""
    agent = SlowAgent()
    task = asyncio.create_task(agent._run_with_telemetry({}))
    await asyncio.sleep(0.05)
    assert fake_cache.hashes["agent_status:slow_test"]["status"] == "running"

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert fake_cache.hashes["agent_status:slow_test"]["status"] == "idle"
    assert _events(fake_cache, "slow_test") == ["task_start", "task_error"]


async def test_parent_timeout_cleans_up_the_child(fake_cache):
    """The supervisor's own timeout cancels its children; they must not be stranded."""
    agent = SlowAgent()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(agent._run_with_telemetry({}), timeout=0.05)
    assert fake_cache.hashes["agent_status:slow_test"]["status"] == "idle"


async def test_successful_run_publishes_start_and_complete(fake_cache):
    await QuickAgent()._run_with_telemetry({})
    assert _events(fake_cache, "quick_test") == ["task_start", "task_complete"]


async def test_pause_does_not_silently_expire(fake_cache):
    await BaseSecurityAgent.pause("threat_detection")
    assert fake_cache.store["agent_paused:threat_detection"] == {"paused": True}
    assert "agent_paused:threat_detection" not in fake_cache.ttls


async def test_escalation_is_queued_durably_and_broadcast(fake_cache):
    await QuickAgent().escalate({"severity": "high", "threat_type": "brute_force"})
    stream = fake_cache.streams[ESCALATION_STREAM]
    assert stream[0][1] == {"agent": "quick_test", "severity": "high", "threat_type": "brute_force"}
    assert fake_cache.messages_on("escalations")[0]["agent"] == "quick_test"


def test_supervisor_has_its_own_larger_budget():
    from agents.supervisor.agent import SupervisorAgent
    from core.config import settings
    assert SupervisorAgent().timeout_seconds == settings.supervisor_timeout_seconds
    assert settings.supervisor_timeout_seconds > settings.agent_timeout_seconds
