"""Unit tests for AgentMemory short-term + blackboard storage."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def memory_with_mock():
    store = {}
    lists = {}
    mock_cache = MagicMock()
    mock_cache.set = AsyncMock(side_effect=lambda k, v, ttl=None: store.update({k: v}))
    mock_cache.get = AsyncMock(side_effect=lambda k: store.get(k))
    mock_cache.delete = AsyncMock(side_effect=lambda k: store.pop(k, None))
    mock_cache.exists = AsyncMock(side_effect=lambda k: k in store)
    mock_cache.lpush = AsyncMock(side_effect=lambda k, v: lists.setdefault(k, []).insert(0, v))
    mock_cache.lrange = AsyncMock(side_effect=lambda k, s, e: lists.get(k, [])[s: None if e == -1 else e + 1])
    mock_cache._redis = MagicMock()
    mock_cache._redis.ltrim = AsyncMock()

    with patch("core.memory.agent_memory.cache", mock_cache):
        from core.memory.agent_memory import AgentMemory
        return AgentMemory("test_agent"), store, lists


@pytest.mark.asyncio
async def test_remember_and_recall(memory_with_mock):
    mem, store, _ = memory_with_mock
    await mem.remember("key1", {"value": 42})
    result = await mem.recall("key1")
    assert result == {"value": 42}


@pytest.mark.asyncio
async def test_forget(memory_with_mock):
    mem, store, _ = memory_with_mock
    await mem.remember("key2", "hello")
    await mem.forget("key2")
    result = await mem.recall("key2")
    assert result is None


@pytest.mark.asyncio
async def test_task_context(memory_with_mock):
    mem, store, _ = memory_with_mock
    ctx = {"incident_id": "abc", "severity": "high"}
    await mem.set_task_context("task-1", ctx)
    result = await mem.get_task_context("task-1")
    assert result == ctx


@pytest.mark.asyncio
async def test_working_memory_structure(memory_with_mock):
    mem, _, _ = memory_with_mock
    wm = mem.new_working_memory()
    assert wm["agent"] == "test_agent"
    assert isinstance(wm["observations"], list)
    assert isinstance(wm["decisions"], list)
    assert isinstance(wm["tool_calls"], list)


@pytest.mark.asyncio
async def test_log_event(memory_with_mock):
    mem, _, lists = memory_with_mock
    await mem.log_event({"type": "task_start", "task_id": "t1"})
    await mem.log_event({"type": "task_end", "task_id": "t1"})
    history = await mem.get_history(limit=10)
    assert len(history) == 2
    assert history[0]["type"] == "task_end"


@pytest.mark.asyncio
async def test_blackboard_set_and_get(memory_with_mock):
    mem, store, _ = memory_with_mock
    await mem.blackboard_set("threat_level", "critical")
    result = await mem.blackboard_get("threat_level")
    assert result == "critical"


@pytest.mark.asyncio
async def test_blackboard_update(memory_with_mock):
    mem, _, _ = memory_with_mock
    await mem.blackboard_set("state", {"a": 1})
    await mem.blackboard_update("state", {"b": 2})
    result = await mem.blackboard_get("state")
    assert result == {"a": 1, "b": 2}


@pytest.mark.asyncio
async def test_namespace_isolation(memory_with_mock):
    mem, store, _ = memory_with_mock
    from core.memory.agent_memory import AgentMemory
    with patch("core.memory.agent_memory.cache", mem._AgentMemory__class__ if hasattr(mem, '__class__') else MagicMock()):
        pass
    await mem.remember("shared_key", "agent_value")
    # Key should be namespaced
    namespaced_key = "agent:test_agent:st:shared_key"
    assert namespaced_key in store
