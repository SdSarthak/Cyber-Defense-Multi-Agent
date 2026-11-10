"""
Repository round trips against a real PostgreSQL, through the real Alembic migrations.

The rest of the suite runs with persistence off, and SQLite accepts what PostgreSQL
rejects: that is how ORM enum labels that did not match the migration, and naive
timestamp columns fed timezone-aware values, shipped with a green test run. Every
insert failed in production and the best-effort repository swallowed the error.

Opt-in: set TEST_POSTGRES_URL to a disposable database, e.g.
    TEST_POSTGRES_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/cd_test
CI runs this against a postgres service container.
"""
import asyncio
import os
import uuid

import pytest
import pytest_asyncio

PG_URL = os.environ.get("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TEST_POSTGRES_URL not set")


def _reset_and_migrate(url: str) -> None:
    from alembic import command
    from sqlalchemy import create_engine, text
    from core.database.base import alembic_config

    sync_url = url.replace("+asyncpg", "+psycopg2")
    engine = create_engine(sync_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()
    command.upgrade(alembic_config(url), "head")


@pytest.fixture(scope="module")
def migrated_db():
    _reset_and_migrate(PG_URL)
    return PG_URL


@pytest_asyncio.fixture
async def repo(migrated_db, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from core.config import settings
    from core.database import repository

    engine = create_async_engine(migrated_db)
    monkeypatch.setattr(settings, "enable_persistence", True)
    monkeypatch.setattr(
        repository, "AsyncSessionLocal",
        async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False),
    )
    yield repository
    await engine.dispose()


def test_migrations_are_at_head(migrated_db):
    from sqlalchemy import create_engine, text
    engine = create_engine(migrated_db.replace("+asyncpg", "+psycopg2"))
    with engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        labels = [r[0] for r in conn.execute(text(
            "SELECT unnest(enum_range(NULL::severitylevel))::text"
        ))]
    engine.dispose()
    assert version == "0003"
    assert labels == ["critical", "high", "medium", "low", "info"]


def test_models_match_the_migrated_schema(migrated_db):
    """
    The ORM and the migrations must describe the same schema. They had drifted on
    enum labels, timestamp types and duplicate index names — each one enough to make
    every write (or `create_all`) fail on PostgreSQL.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine
    import core.database.models  # noqa: F401 — registers the tables
    from core.database.base import Base

    engine = create_engine(migrated_db.replace("+asyncpg", "+psycopg2"))
    with engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(context, Base.metadata)
    engine.dispose()
    assert diff == [], f"models and migrations disagree: {diff}"


def test_create_all_builds_on_an_empty_database(migrated_db):
    """`Base.metadata.create_all` must be valid DDL (it used to collide on index names)."""
    from sqlalchemy import create_engine, text
    import core.database.models  # noqa: F401
    from core.database.base import Base

    engine = create_engine(migrated_db.replace("+asyncpg", "+psycopg2"), isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS create_all_check CASCADE"))
        conn.execute(text("CREATE SCHEMA create_all_check"))
        conn.execute(text("SET search_path TO create_all_check"))
        Base.metadata.create_all(conn)
        conn.execute(text("DROP SCHEMA create_all_check CASCADE"))
    engine.dispose()


async def test_threat_event_round_trip(repo):
    event_id = await repo.save_threat_event(
        {"source_ip": "203.0.113.9", "message": "nmap scan"},
        {"threat_type": "port_scan", "severity": "HIGH", "confidence": 0.9},
    )
    assert event_id, "insert was rejected (enum labels / types out of sync with the migration?)"
    recent = await repo.recent_threat_events(limit=5)
    assert recent[0]["severity"] == "high"
    assert (await repo.threat_severity_counts(hours=1))["high"] >= 1


async def test_incident_resolution_persists_timezone_aware_timestamp(repo):
    incident_id = await repo.save_incident(
        {"title": "Brute force", "severity": "critical", "affected_assets": ["198.51.100.7"]},
        {"playbook": "brute_force", "containment_actions": [
            {"action": "Block IP", "automated": True, "status": "pending_approval"}]},
    )
    assert incident_id
    updated = await repo.update_incident(incident_id, "resolved", "closed out")
    assert updated is not None, "resolving failed (naive resolved_at column?)"
    assert updated["status"] == "resolved"
    assert updated["resolved_at"]
    assert updated["timeline"][-1]["event"] == "closed out"

    action = await repo.update_containment_action(incident_id, 0, "simulated", {"executor": "simulate"})
    assert action["status"] == "simulated"


async def test_threat_events_link_to_their_incident(repo):
    event_id = await repo.save_threat_event(
        {"source_ip": "192.0.2.44"}, {"threat_type": "brute_force", "severity": "high"}
    )
    incident_id = await repo.save_incident(
        {"title": "Linked", "affected_assets": ["192.0.2.44"]}, {"playbook": "brute_force"},
        threat_event_ids=[event_id],
    )
    linked = [t for t in await repo.recent_threat_events(limit=50) if t["id"] == event_id]
    assert linked[0]["incident_id"] == incident_id
    metrics = await repo.incident_metrics(hours=1)
    assert metrics["total_incidents"] >= 1
    assert metrics["mean_time_to_detect_hours"] is not None


async def test_heartbeat_upserts_registry(repo):
    await repo.record_agent_heartbeat("threat_detection", "running", current_task="t-1")
    await repo.record_agent_heartbeat("threat_detection", "idle", completed=True)
    rows = {r["agent_name"]: r for r in await repo.list_agent_registry()}
    assert rows["threat_detection"]["status"] == "idle"
    assert rows["threat_detection"]["last_heartbeat"], "heartbeat write failed (naive column?)"
    assert rows["threat_detection"]["tasks_completed"] == 1


async def test_vulnerability_and_compliance_round_trip(repo):
    assert await repo.save_vulnerability(
        {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "CRITICAL"},
        {"risk_score": 9.8, "affected_assets": ["app-01", "10.0.0.5"], "remediation": "upgrade"},
    )
    vuln = (await repo.list_vulnerabilities(limit=5))[0]
    assert vuln["severity"] == "critical"
    assert vuln["asset_ip"] == "10.0.0.5"
    assert vuln["patch_available"] is False

    evaluation = str(uuid.uuid4())
    written = await repo.save_compliance_results("SOC2", [
        {"control_id": "CC6.1", "control_name": "Access", "status": "pass", "score": 90,
         "risk_if_failed": "high", "evidence": {"platform": {"mfa": True}}, "remediation": "none"},
        {"control_id": "CC7.1", "control_name": "Monitoring", "status": "fail", "score": 30},
    ], evaluation_id=evaluation)
    assert written == 2
    history = await repo.compliance_history(framework="SOC2")
    assert {h["evaluation_id"] for h in history} == {evaluation}
    assert any(h["score"] == 90 and '"mfa": true' in h["evidence"] for h in history)
    summary = await repo.compliance_summary()
    assert summary["SOC2"] == {"controls": 2, "passed": 1, "failed": 1, "score": 60.0}


async def test_agent_action_links_only_real_incidents(repo):
    incident_id = await repo.save_incident({"title": "x"}, {"playbook": "default"})
    assert await repo.save_agent_action("incident_response", "run", incident_id=incident_id)
    # A Redis-only id must not trip the foreign key and lose the audit row.
    assert await repo.save_agent_action("incident_response", "run", incident_id=str(uuid.uuid4()))
