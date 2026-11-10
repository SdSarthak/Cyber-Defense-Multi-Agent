"""The shared threat level: raises apply at once, quiet runs cannot undo them early."""
import time

import pytest

from core import threat_level as tl
from core.config import settings


@pytest.fixture(autouse=True)
def hold(monkeypatch):
    monkeypatch.setattr(settings, "threat_level_hold_seconds", 900)


async def test_raising_applies_immediately(fake_cache):
    assert await tl.propose("high", "threat_detection") == "high"
    assert await tl.propose("critical", "escalation") == "critical"
    assert fake_cache.store["blackboard:threat_level"] == "critical"


async def test_a_quiet_run_cannot_lower_a_fresh_level(fake_cache):
    """This used to be last-writer-wins: a benign run reset a critical banner to LOW."""
    await tl.propose("critical", "escalation")
    assert await tl.propose("low", "supervisor") == "critical"
    assert fake_cache.store["blackboard:threat_level"] == "critical"


async def test_lowering_applies_once_the_level_has_stood(fake_cache):
    await tl.propose("critical", "escalation")
    fake_cache.store["blackboard:threat_level_meta"]["set_at"] = time.time() - 1000
    assert await tl.propose("medium", "supervisor") == "medium"


async def test_human_override_can_lower_and_is_attributed(fake_cache):
    await tl.propose("critical", "escalation")
    assert await tl.override("low", user="admin") == "low"
    assert fake_cache.store["blackboard:threat_level_meta"]["source"] == "human:admin"


async def test_override_rejects_unknown_levels(fake_cache):
    with pytest.raises(ValueError):
        await tl.override("banana", user="admin")
    assert "blackboard:threat_level" not in fake_cache.store


async def test_unknown_proposal_is_treated_as_low(fake_cache):
    assert await tl.propose("banana", "supervisor") == "low"


@pytest.mark.parametrize("raw,expected", [
    ("HIGH", "high"), (" critical ", "critical"), ("info", "low"), ("normal", "low"),
    (None, None), ("severe", None),
])
def test_normalize(raw, expected):
    assert tl.normalize(raw) == expected
