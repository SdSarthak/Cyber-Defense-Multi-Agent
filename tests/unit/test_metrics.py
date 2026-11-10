"""Prometheus label hygiene: anonymous traffic and LLM prose must not mint series."""
import pytest
from prometheus_client import REGISTRY

from core import metrics


def _handlers() -> set[str]:
    return {
        s.labels["handler"]
        for m in REGISTRY.collect() if m.name == "http_requests"
        for s in m.samples if "handler" in s.labels
    }


async def test_junk_and_rejected_requests_do_not_create_per_path_labels(api_client):
    for i in range(5):
        await api_client.get(f"/no-such-path-{i}")
        await api_client.get(f"/api/v1/incidents/{i}")  # 401 before routing runs
    handlers = _handlers()
    assert metrics.UNMATCHED_HANDLER in handlers
    assert "/api/v1/incidents/{incident_id}" in handlers
    assert not any(h.startswith("/no-such-path-") for h in handlers)
    assert not ({f"/api/v1/incidents/{i}" for i in range(5)} & handlers)


@pytest.mark.parametrize("raw,expected", [
    ("brute_force", "brute_force"), ("Brute-Force (SSH)", "brute_force"),
    ("SQL Injection", "sql_injection"), ("weird new thing", "other"), (None, "other"),
])
def test_threat_type_label(raw, expected):
    assert metrics.threat_type_label(raw) == expected


@pytest.mark.parametrize("raw,expected", [("HIGH", "high"), ("info", "info"), ("severe", "unknown")])
def test_severity_label(raw, expected):
    assert metrics.severity_label(raw) == expected
