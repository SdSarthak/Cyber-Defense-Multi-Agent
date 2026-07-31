"""
Tests for the persistence layer's coercion and gating logic.

`repository` is the boundary where free-form LLM output meets a typed schema: a model
that answers "Critical!" or a CVSS score of "9.8" as a string must not blow up a
commit or silently land as the wrong enum. None of that was covered, and none of it
needs a database — the pure helpers are tested directly and the writers are checked
against a stubbed session.
"""
import uuid
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest

from core.database import repository
from core.database.models import IncidentStatus, SeverityLevel


class TestCoerceSeverity:
    @pytest.mark.parametrize("value,expected", [
        ("critical", SeverityLevel.CRITICAL),
        ("HIGH", SeverityLevel.HIGH),
        ("  medium  ", SeverityLevel.MEDIUM),
        ("Low", SeverityLevel.LOW),
        ("info", SeverityLevel.INFO),
    ])
    def test_recognised_values(self, value, expected):
        assert repository.coerce_severity(value) is expected

    def test_an_already_typed_severity_survives_a_round_trip(self):
        """
        `str()` on a (str, Enum) member is "SeverityLevel.HIGH" up to Python 3.10 and
        "high" from 3.11 — so an enum passed back in used to degrade to MEDIUM on one
        interpreter and pass on the other.
        """
        assert repository.coerce_severity(SeverityLevel.HIGH) is SeverityLevel.HIGH
        assert repository.coerce_severity(SeverityLevel.INFO) is SeverityLevel.INFO

    @pytest.mark.parametrize("value", [None, "", "  ", "critical!", "sev1", 7, [], {}])
    def test_unrecognised_values_fall_back(self, value):
        assert repository.coerce_severity(value) is SeverityLevel.MEDIUM

    def test_explicit_default_is_honoured(self):
        assert repository.coerce_severity("nonsense", SeverityLevel.INFO) is SeverityLevel.INFO


class TestCoerceIncidentStatus:
    @pytest.mark.parametrize("value,expected", [
        ("open", IncidentStatus.OPEN),
        ("FALSE_POSITIVE", IncidentStatus.FALSE_POSITIVE),
        ("  Contained ", IncidentStatus.CONTAINED),
    ])
    def test_recognised_values(self, value, expected):
        assert repository.coerce_incident_status(value) is expected

    def test_an_already_typed_status_survives_a_round_trip(self):
        assert repository.coerce_incident_status(IncidentStatus.RESOLVED) is IncidentStatus.RESOLVED

    @pytest.mark.parametrize("value", [None, "closed", "false positive", 3])
    def test_unrecognised_values_fall_back(self, value):
        assert repository.coerce_incident_status(value) is IncidentStatus.OPEN


class TestSeverityFromCvss:
    @pytest.mark.parametrize("score,expected", [
        (10.0, SeverityLevel.CRITICAL),
        (9.0, SeverityLevel.CRITICAL),
        (8.9, SeverityLevel.HIGH),
        (7.0, SeverityLevel.HIGH),
        (6.9, SeverityLevel.MEDIUM),
        (4.0, SeverityLevel.MEDIUM),
        (3.9, SeverityLevel.LOW),
        (0.1, SeverityLevel.LOW),
        (0.0, SeverityLevel.INFO),
    ])
    def test_nvd_band_boundaries(self, score, expected):
        """Every band edge is inclusive at the bottom — an 8.9 is High, a 9.0 Critical."""
        assert repository.severity_from_cvss(score) is expected

    def test_missing_score_is_medium_not_info(self):
        assert repository.severity_from_cvss(None) is SeverityLevel.MEDIUM

    def test_negative_score_is_not_treated_as_low(self):
        assert repository.severity_from_cvss(-1.0) is SeverityLevel.INFO


class TestAsUuid:
    def test_uuid_instance_passes_through(self):
        value = uuid.uuid4()
        assert repository._as_uuid(value) is value

    def test_uuid_string_is_parsed(self):
        text = "6f1c9a4e-6f1f-4d2b-9a3d-2f7c1b0a5e11"
        assert repository._as_uuid(text) == uuid.UUID(text)

    def test_uuid_without_dashes_is_parsed(self):
        assert repository._as_uuid("6f1c9a4e6f1f4d2b9a3d2f7c1b0a5e11") is not None

    @pytest.mark.parametrize("value", [None, "", "INC-2026-001", "not-a-uuid", 42, [], {"a": 1}])
    def test_llm_labels_become_none_rather_than_raising(self, value):
        """The model happily invents ids like "INC-2026-001"; those must not reach the DB."""
        assert repository._as_uuid(value) is None


class TestClip:
    def test_none_stays_none(self):
        assert repository._clip(None, 10) is None

    def test_short_value_is_untouched(self):
        assert repository._clip("abc", 10) == "abc"

    def test_exact_length_is_not_clipped(self):
        assert repository._clip("abcde", 5) == "abcde"

    def test_overlong_value_is_truncated_to_the_column_width(self):
        assert repository._clip("a" * 100, 45) == "a" * 45

    def test_non_string_is_stringified_first(self):
        assert repository._clip(1234567, 4) == "1234"

    def test_unicode_is_clipped_by_character_not_byte(self):
        assert repository._clip("攻撃" * 50, 4) == "攻撃攻撃"


class TestNumericCoercion:
    @pytest.mark.parametrize("value,expected", [
        (5, 5), ("5", 5), (5.9, 5), (True, 1),
    ])
    def test_to_int(self, value, expected):
        assert repository._to_int(value) == expected

    @pytest.mark.parametrize("value", [None, "", "high", "5.5.5", [], {}])
    def test_to_int_rejects_junk(self, value):
        assert repository._to_int(value) is None

    @pytest.mark.parametrize("value,expected", [(9.8, 9.8), ("9.8", 9.8), (7, 7.0)])
    def test_to_float(self, value, expected):
        assert repository._to_float(value) == expected

    @pytest.mark.parametrize("value", [None, "", "critical", [], {}])
    def test_to_float_rejects_junk(self, value):
        assert repository._to_float(value) is None


class TestJsonable:
    def test_none_stays_none(self):
        assert repository._jsonable(None) is None

    def test_plain_payload_round_trips(self):
        assert repository._jsonable({"a": [1, {"b": 2}]}) == {"a": [1, {"b": 2}]}

    def test_unserialisable_values_are_stringified(self):
        out = repository._jsonable({"when": uuid.uuid4()})
        assert isinstance(out["when"], str)

    def test_oversized_payload_is_truncated_with_a_marker(self):
        """An audit row must never carry a multi-megabyte agent payload."""
        out = repository._jsonable({"blob": "x" * 20000})
        assert out["truncated"] is True
        assert len(out["preview"]) == 8000

    def test_payload_just_under_the_cap_is_kept_whole(self):
        payload = {"blob": "x" * 100}
        assert repository._jsonable(payload) == payload


class TestPersistenceDisabled:
    """
    Every writer is a no-op with ENABLE_PERSISTENCE=false — the contract that lets the
    mesh (and this suite) run with no PostgreSQL anywhere.
    """

    async def test_writers_short_circuit(self, monkeypatch):
        from core.config import settings

        monkeypatch.setattr(settings, "enable_persistence", False)
        assert await repository.save_threat_event({}, {}) is None
        assert await repository.save_incident({}, {}) is None
        assert await repository.save_vulnerability({"cve_id": "CVE-2021-44228"}, {}) is None
        assert await repository.save_agent_action("a", "run") is None
        assert await repository.save_compliance_results("SOC2", [{"control_id": "CC6.1"}]) == 0
        assert await repository.save_log_entries([{"message": "x"}]) == 0
        assert await repository.record_agent_heartbeat("a", "idle") is None

    async def test_readers_return_empty(self, monkeypatch):
        from core.config import settings

        monkeypatch.setattr(settings, "enable_persistence", False)
        assert await repository.recent_threat_events() == []
        assert await repository.list_incidents() == []
        assert await repository.list_vulnerabilities() == []
        assert await repository.compliance_history() == []
        assert await repository.list_agent_registry() == []
        assert await repository.threat_severity_counts() == {}
        assert await repository.count_open_incidents() == 0
        assert await repository.get_incident("6f1c9a4e-6f1f-4d2b-9a3d-2f7c1b0a5e11") is None


class _StubSession:
    def __init__(self):
        self.added = []
        self.commits = 0

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.commits += 1


@pytest.fixture
def stub_session(monkeypatch):
    session = _StubSession()

    @asynccontextmanager
    async def _factory():
        yield session

    monkeypatch.setattr(repository, "AsyncSessionLocal", lambda: _factory())
    return session


class TestSaveLogEntries:
    async def test_row_count_reflects_rows_actually_written(self, monkeypatch, stub_session):
        """
        A batch carrying junk used to report every offered entry as stored, so the
        dashboard showed "Stored 5 rows" for a batch that wrote 2.
        """
        from core.config import settings

        monkeypatch.setattr(settings, "enable_persistence", True)
        logs = [{"message": "a"}, "not a dict", None, {"message": "b"}, 42]
        written = await repository.save_log_entries(logs)
        assert written == 2
        assert len(stub_session.added) == 2

    async def test_anomaly_index_flags_the_matching_row(self, monkeypatch, stub_session):
        from core.config import settings

        monkeypatch.setattr(settings, "enable_persistence", True)
        logs = [{"message": "clean"}, {"message": "brute force"}]
        await repository.save_log_entries(logs, {1: {"severity": "critical"}})
        clean, flagged = stub_session.added
        assert clean.is_anomalous is False
        assert clean.anomaly_score == 0.0
        assert flagged.is_anomalous is True
        assert flagged.anomaly_score == 1.0

    async def test_unknown_anomaly_severity_gets_the_middle_score(
        self, monkeypatch, stub_session
    ):
        from core.config import settings

        monkeypatch.setattr(settings, "enable_persistence", True)
        await repository.save_log_entries([{"message": "x"}], {0: {"severity": "spicy"}})
        assert stub_session.added[0].anomaly_score == 0.5

    async def test_empty_batch_writes_nothing(self, monkeypatch, stub_session):
        from core.config import settings

        monkeypatch.setattr(settings, "enable_persistence", True)
        assert await repository.save_log_entries([]) == 0
        assert stub_session.commits == 0

    async def test_database_failure_is_swallowed_not_raised(self, monkeypatch):
        """The mesh must keep analysing traffic when PostgreSQL is unreachable."""
        from core.config import settings

        monkeypatch.setattr(settings, "enable_persistence", True)

        @asynccontextmanager
        async def _broken():
            raise ConnectionRefusedError("postgres down")
            yield  # pragma: no cover

        monkeypatch.setattr(repository, "AsyncSessionLocal", lambda: _broken())
        assert await repository.save_log_entries([{"message": "x"}]) == 0
        assert await repository.recent_threat_events() == []
