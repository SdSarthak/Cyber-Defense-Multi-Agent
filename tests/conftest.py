"""
Shared test fixtures.

Two things matter for these tests to be meaningful:

1. **One patch point for Redis.** Application code reaches the cache through
   ``redis_client.cache`` (module attribute) rather than importing the singleton by
   value, so replacing that single attribute swaps the backing store process-wide.
   Patching a per-module ``cache`` name would leave every already-imported module
   still talking to a real Redis.

2. **No external services.** The autouse ``isolate_backends`` fixture turns off
   PostgreSQL persistence, Elasticsearch and ChromaDB retrieval, so a unit test never
   silently depends on a container being up.
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from langchain_core.messages import AIMessage
from langchain_core.runnables import Runnable

from core.config import settings


# ── Fake Redis ────────────────────────────────────────────────────────────────

class FakeRedisCache:
    """In-memory stand-in implementing the RedisCache surface used by the app."""

    def __init__(self):
        self.store: dict = {}
        self.lists: dict[str, list] = {}
        self.hashes: dict[str, dict] = {}
        self.published: list[tuple[str, dict]] = []

    def _roundtrip(self, value):
        """Match real Redis semantics: values are JSON-serialised on the way in."""
        return json.loads(json.dumps(value, default=str))

    async def set(self, key, value, ttl=3600):
        self.store[key] = self._roundtrip(value)

    async def get(self, key):
        return self.store.get(key)

    async def delete(self, key):
        self.store.pop(key, None)

    async def exists(self, key):
        return key in self.store

    async def expire(self, key, ttl):
        return None

    async def publish(self, channel, message):
        self.published.append((channel, self._roundtrip(message)))

    async def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, self._roundtrip(value))

    async def rpop(self, key):
        items = self.lists.get(key)
        return items.pop() if items else None

    async def lrange(self, key, start=0, end=-1):
        items = self.lists.get(key, [])
        return items[start:] if end == -1 else items[start:end + 1]

    async def ltrim(self, key, start, end):
        items = self.lists.get(key)
        if items is not None:
            self.lists[key] = items[start:] if end == -1 else items[start:end + 1]

    async def llen(self, key):
        return len(self.lists.get(key, []))

    async def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1
        return self.store[key]

    async def set_if_absent(self, key, value, ttl):
        if key in self.store:
            return False
        self.store[key] = self._roundtrip(value)
        return True

    async def hset(self, name, mapping):
        self.hashes.setdefault(name, {}).update(
            {k: self._roundtrip(v) for k, v in mapping.items()}
        )

    async def hgetall(self, name):
        return dict(self.hashes.get(name, {}))

    # Test helpers ------------------------------------------------------------

    def messages_on(self, channel: str) -> list[dict]:
        return [payload for ch, payload in self.published if ch == channel]


@pytest.fixture(autouse=True)
def isolate_backends(monkeypatch):
    """Keep every test off PostgreSQL, Elasticsearch and ChromaDB."""
    monkeypatch.setattr(settings, "enable_persistence", False)
    monkeypatch.setattr(settings, "elasticsearch_enabled", False)
    monkeypatch.setattr(settings, "rag_enabled", False)
    monkeypatch.setattr(settings, "agent_timeout_seconds", 30)


@pytest.fixture(autouse=True)
def fake_cache(monkeypatch):
    """Replace the Redis singleton for the whole process."""
    fake = FakeRedisCache()
    monkeypatch.setattr("core.database.redis_client.cache", fake)
    return fake


@pytest.fixture
def mock_redis(fake_cache):
    """Back-compat shape: (cache, store, published)."""
    return fake_cache, fake_cache.store, fake_cache.published


# ── LLM stubs ─────────────────────────────────────────────────────────────────

CANNED_RESPONSES = {
    "threat": {
        "threat_type": "port_scan", "severity": "high", "confidence": 0.9,
        "indicators": ["185.220.101.45"], "mitre_tactics": ["Reconnaissance"],
        "mitre_techniques": ["T1046"], "reasoning": "Sequential port scan detected",
        "should_escalate": True,
    },
    "log": {
        "anomaly_count": 3, "total_analyzed": 10,
        "anomalies": [
            {"log_index": 0, "anomaly_type": "brute_force", "severity": "high",
             "source": "185.220.101.45", "description": "50 failed logins", "action": "block_ip"},
        ],
        "patterns_detected": ["brute_force"], "risk_summary": "Brute force detected",
    },
    "vuln": {
        "risk_score": 9.8, "exploitability": "high", "business_impact": "critical",
        "patch_urgency": "immediate", "remediation": "Apply patch immediately",
        "workaround": "Disable feature X", "affected_assets": ["10.0.1.1"],
        "summary": "Critical RCE vulnerability",
    },
    "incident": {
        "incident_id": "6f1c9a4e-6f1f-4d2b-9a3d-2f7c1b0a5e11", "playbook": "brute_force",
        "priority": "p1",
        "containment_actions": [{"action": "Block IP", "automated": True, "status": "pending"}],
        "investigation_steps": ["Review auth logs"], "communication_plan": {},
        "timeline": [], "estimated_resolution": "2h", "lessons_learned": [],
    },
    "compliance": {
        "status": "partial", "score": 65.0, "findings": ["MFA not enforced"],
        "evidence_quality": "moderate", "remediation": "Enable MFA",
        "risk_if_failed": "high",
    },
    "report": {
        "executive_summary": "Security posture is moderate with active threats.",
        "threat_landscape": {"current_threats": ["brute_force"], "trend": "stable"},
        "key_metrics": {"total_incidents": 5, "critical_incidents": 1,
                        "mean_time_to_detect_hours": 0.5, "mean_time_to_respond_hours": 1.2,
                        "vulnerabilities_open": 12, "compliance_score": 72.0},
        "top_risks": [], "recommended_actions": [], "compliance_status": {}, "period": "2026-05",
    },
    "router": {
        "agents": ["threat_detection"], "reasoning": "Single threat event",
        "priority": "high", "parallel": False,
    },
}


class StubChatModel(Runnable):
    """
    Deterministic stand-in for ChatGoogleGenerativeAI.

    It must be a real ``Runnable``: agents build their chains as ``PROMPT | self.llm``,
    and LangChain coerces a plain MagicMock into a ``RunnableLambda``. The mock would
    then be invoked with the PromptValue and return another mock, whose ``.content``
    is not JSON — so every agent would silently take its parse-failure fallback and
    the test would assert against the fallback instead of the intended verdict.
    """

    def __init__(self, response):
        self.content = response if isinstance(response, str) else json.dumps(response)
        self.calls: list = []

    def invoke(self, input, config=None, **kwargs):
        self.calls.append(input)
        return AIMessage(content=self.content)

    async def ainvoke(self, input, config=None, **kwargs):
        self.calls.append(input)
        return AIMessage(content=self.content)


def make_llm(response) -> StubChatModel:
    """Build a stub chat model whose ainvoke always returns `response` as content."""
    return StubChatModel(response)


def patch_llm(response):
    """
    Context manager patching the Gemini class at its source module.

    ``BaseSecurityAgent.llm`` imports ``ChatGoogleGenerativeAI`` inside the property,
    so patching ``langchain_google_genai.ChatGoogleGenerativeAI`` takes effect no
    matter which module imported the agent first.
    """
    return patch(
        "langchain_google_genai.ChatGoogleGenerativeAI",
        return_value=make_llm(response),
    )


@pytest.fixture
def mock_llm():
    """Patch Gemini so every agent gets a plausible canned JSON answer."""
    def fake_factory(*args, **kwargs):
        return make_llm(CANNED_RESPONSES["threat"])

    with patch("langchain_google_genai.ChatGoogleGenerativeAI", side_effect=fake_factory):
        yield CANNED_RESPONSES


# ── Sample data ───────────────────────────────────────────────────────────────

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


# ── API fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def mock_supervisor():
    """Stand-in supervisor with the surface the routes call."""
    sup = MagicMock()
    sup.agent_names = [
        "threat_detection", "log_analysis", "vulnerability_intel",
        "incident_response", "compliance", "reporting",
    ]
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
    sup.handle_escalation = AsyncMock(return_value={})
    return sup


@pytest.fixture
def auth_token() -> str:
    from api.middleware.auth import create_access_token
    return create_access_token("admin", role="admin")


@pytest.fixture
def auth_headers(auth_token) -> dict:
    return {"Authorization": f"Bearer {auth_token}"}


@pytest_asyncio.fixture
async def api_client(mock_supervisor):
    """
    HTTPX client bound to the ASGI app.

    ``ASGITransport`` does not run lifespan events, so ``app.state.supervisor`` is
    injected explicitly — without it every route that dispatches to an agent would
    fail with AttributeError rather than exercising the handler.
    """
    from api.main import app
    app.state.supervisor = mock_supervisor
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
