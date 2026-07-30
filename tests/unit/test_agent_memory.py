"""Unit tests for AgentMemory short-term + blackboard storage."""
import pytest

from core.memory.agent_memory import HISTORY_LIMIT, AgentMemory


@pytest.fixture
def memory(fake_cache):
    """AgentMemory backed by the autouse in-memory cache from conftest."""
    return AgentMemory("test_agent")


async def test_remember_and_recall(memory):
    await memory.remember("key1", {"value": 42})
    assert await memory.recall("key1") == {"value": 42}


async def test_recall_missing_key_returns_none(memory):
    assert await memory.recall("never_set") is None


async def test_forget(memory):
    await memory.remember("key2", "hello")
    await memory.forget("key2")
    assert await memory.recall("key2") is None


async def test_task_context(memory):
    ctx = {"incident_id": "abc", "severity": "high"}
    await memory.set_task_context("task-1", ctx)
    assert await memory.get_task_context("task-1") == ctx


def test_working_memory_structure(memory):
    wm = memory.new_working_memory()
    assert wm["agent"] == "test_agent"
    assert isinstance(wm["observations"], list)
    assert isinstance(wm["decisions"], list)
    assert isinstance(wm["tool_calls"], list)
    assert wm["started_at"]


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


async def test_namespace_isolation(memory, fake_cache):
    other = AgentMemory("other_agent")
    await memory.remember("shared_key", "agent_value")
    await other.remember("shared_key", "other_value")

    assert "agent:test_agent:st:shared_key" in fake_cache.store
    assert "agent:other_agent:st:shared_key" in fake_cache.store
    assert await memory.recall("shared_key") == "agent_value"
    assert await other.recall("shared_key") == "other_value"
