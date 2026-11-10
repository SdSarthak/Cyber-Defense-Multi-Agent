"""Unit tests for AgentMemory history + blackboard storage."""
import pytest

from core.memory.agent_memory import HISTORY_LIMIT, AgentMemory


@pytest.fixture
def memory(fake_cache):
    """AgentMemory backed by the autouse in-memory cache from conftest."""
    return AgentMemory("test_agent")


async def test_log_event(memory):
    await memory.log_event({"type": "task_start", "task_id": "t1"})
    await memory.log_event({"type": "task_end", "task_id": "t1"})
    history = await memory.get_history(limit=10)
    assert len(history) == 2
    assert history[0]["type"] == "task_end"
    assert "ts" in history[0]


async def test_log_event_does_not_mutate_caller_dict(memory):
    event = {"type": "task_start"}
    await memory.log_event(event)
    assert "ts" not in event


async def test_history_is_capped(memory, fake_cache):
    for i in range(HISTORY_LIMIT + 25):
        await memory.log_event({"type": "tick", "i": i})
    assert len(fake_cache.lists["agent:test_agent:history"]) == HISTORY_LIMIT


async def test_log_event_survives_redis_failure(memory, fake_cache):
    async def boom(*args, **kwargs):
        raise ConnectionError("redis down")

    fake_cache.lpush = boom
    # Telemetry must never take down an analysis run.
    await memory.log_event({"type": "task_start"})


async def test_blackboard_set_and_get(memory):
    await memory.blackboard_set("threat_level", "critical")
    assert await memory.blackboard_get("threat_level") == "critical"


async def test_blackboard_update(memory):
    await memory.blackboard_set("state", {"a": 1})
    await memory.blackboard_update("state", {"b": 2})
    assert await memory.blackboard_get("state") == {"a": 1, "b": 2}


async def test_blackboard_update_on_missing_key_creates_it(memory):
    await memory.blackboard_update("fresh", {"a": 1})
    assert await memory.blackboard_get("fresh") == {"a": 1}


async def test_blackboard_update_replaces_non_dict_value(memory):
    """A scalar left on the blackboard must not break a later dict update."""
    await memory.blackboard_set("state", "critical")
    await memory.blackboard_update("state", {"b": 2})
    assert await memory.blackboard_get("state") == {"b": 2}


async def test_history_is_namespaced_per_agent(memory, fake_cache):
    other = AgentMemory("other_agent")
    await memory.log_event({"type": "mine"})
    await other.log_event({"type": "theirs"})

    assert [e["type"] for e in await memory.get_history()] == ["mine"]
    assert [e["type"] for e in await other.get_history()] == ["theirs"]
