"""
Authorisation and input-bound tests for the REST surface.

Two classes of defect are covered here:

1. **Role escalation.** The WebSocket refuses `pause_agent` / `resume_agent` /
   `run_agent` from a non-admin role, but the equivalent REST routes accepted any
   valid token — an analyst locked out of the dashboard buttons could pause the whole
   agent mesh with one `curl`.
2. **Unbounded list reads.** Every "recent items" route computed a Redis range as
   ``lrange(0, limit - 1)``. With ``limit=0`` that is ``lrange(0, -1)``, i.e. *the
   entire list* — the opposite of what the caller asked for, and an unbounded response.
"""
import pytest

from api.middleware.auth import create_access_token


@pytest.fixture
def analyst_headers() -> dict:
    return {"Authorization": f"Bearer {create_access_token('analyst', role='analyst')}"}


@pytest.fixture
def admin_headers() -> dict:
    return {"Authorization": f"Bearer {create_access_token('admin', role='admin')}"}


ADMIN_ONLY_CALLS = [
    ("post", "/api/v1/agents/threat_detection/pause", None),
    ("post", "/api/v1/agents/threat_detection/resume", None),
    ("post", "/api/v1/agents/run", {"agent": "threat_detection", "payload": {}}),
    ("post", "/api/v1/agents/supervisor/run", {}),
]

READ_ONLY_CALLS = [
    "/api/v1/agents/status",
    "/api/v1/agents/registry",
    "/api/v1/agents/blackboard",
    "/api/v1/threats/recent",
    "/api/v1/incidents/",
]


class TestAdminOnlyRoutes:
    @pytest.mark.parametrize("method,path,body", ADMIN_ONLY_CALLS)
    async def test_analyst_is_refused(self, api_client, analyst_headers, method, path, body):
        resp = await getattr(api_client, method)(path, json=body, headers=analyst_headers)
        assert resp.status_code == 403, resp.text
        assert "analyst" in resp.json()["detail"]

    @pytest.mark.parametrize("method,path,body", ADMIN_ONLY_CALLS)
    async def test_admin_is_allowed(self, api_client, admin_headers, method, path, body):
        resp = await getattr(api_client, method)(path, json=body, headers=admin_headers)
        assert resp.status_code == 200, resp.text

    @pytest.mark.parametrize("method,path,body", ADMIN_ONLY_CALLS)
    async def test_anonymous_is_still_401_not_403(self, api_client, method, path, body):
        """An unauthenticated caller must not learn that the route exists but is admin-only."""
        resp = await getattr(api_client, method)(path, json=body)
        assert resp.status_code == 401

    async def test_analyst_cannot_pause_via_a_refused_call(
        self, api_client, analyst_headers, admin_headers, fake_cache
    ):
        await api_client.post(
            "/api/v1/agents/threat_detection/pause", headers=analyst_headers
        )
        status = await api_client.get("/api/v1/agents/status", headers=admin_headers)
        assert status.json()["threat_detection"]["paused"] is False

    @pytest.mark.parametrize("path", READ_ONLY_CALLS)
    async def test_analyst_keeps_read_access(self, api_client, analyst_headers, path):
        resp = await api_client.get(path, headers=analyst_headers)
        assert resp.status_code == 200, resp.text


class TestPublicPrefixMatching:
    async def test_auth_prefix_does_not_exempt_a_sibling_path(self, api_client):
        """
        `/api/v1/auth` is public. Matching it with a bare `startswith` would also
        exempt `/api/v1/authanything` — a 404 is correct, a 200 would mean the route
        ran unauthenticated.
        """
        from api.middleware.auth import AuthMiddleware

        assert AuthMiddleware._is_public("/api/v1/auth/login")
        assert AuthMiddleware._is_public("/health/ready")
        assert not AuthMiddleware._is_public("/api/v1/authorisation")
        assert not AuthMiddleware._is_public("/healthcheck-internal")
        assert not AuthMiddleware._is_public("/api/v1/agents/status")


class TestListLimitBounds:
    LIMITED = [
        "/api/v1/threats/recent",
        "/api/v1/incidents/",
        "/api/v1/reports/",
        "/api/v1/vulnerabilities/",
        "/api/v1/compliance/history",
        "/api/v1/agents/threat_detection/history",
    ]

    @pytest.mark.parametrize("path", LIMITED)
    @pytest.mark.parametrize("limit", [0, -1, -100])
    async def test_non_positive_limit_is_rejected(self, api_client, auth_headers, path, limit):
        resp = await api_client.get(f"{path}?limit={limit}", headers=auth_headers)
        assert resp.status_code == 422, resp.text

    @pytest.mark.parametrize("path", LIMITED)
    async def test_oversized_limit_is_rejected(self, api_client, auth_headers, path):
        resp = await api_client.get(f"{path}?limit=100000", headers=auth_headers)
        assert resp.status_code == 422, resp.text

    @pytest.mark.parametrize("path", LIMITED)
    async def test_non_numeric_limit_is_rejected(self, api_client, auth_headers, path):
        resp = await api_client.get(f"{path}?limit=all", headers=auth_headers)
        assert resp.status_code == 422, resp.text

    async def test_limit_actually_truncates_a_redis_backed_list(
        self, api_client, auth_headers, fake_cache
    ):
        for i in range(10):
            await fake_cache.lpush("agent:threat_detection:history", {"i": i})
        resp = await api_client.get(
            "/api/v1/agents/threat_detection/history?limit=3", headers=auth_headers
        )
        assert resp.status_code == 200
        assert len(resp.json()["history"]) == 3
