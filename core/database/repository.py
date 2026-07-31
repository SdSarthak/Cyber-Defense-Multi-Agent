"""
Persistence layer bridging agent output to the PostgreSQL schema.

Every function here is best-effort: the SOC mesh must keep analysing traffic even if
the database is unreachable, so failures are logged and reported as ``None``/empty
rather than raised. Redis remains the low-latency path for live dashboard state;
PostgreSQL is the durable system of record.

Set ``ENABLE_PERSISTENCE=false`` to run the mesh entirely in-memory.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum as PyEnum
from typing import Any

import structlog
from sqlalchemy import desc, func, select

from core.config import settings
from core.database.base import AsyncSessionLocal
from core.database.models import (
    AgentAction,
    AgentRegistry,
    AgentStatus,
    ComplianceCheck,
    Incident,
    IncidentStatus,
    LogEntry,
    SeverityLevel,
    ThreatEvent,
    Vulnerability,
)

log = structlog.get_logger()

_VALID_SEVERITIES = {s.value for s in SeverityLevel}
_VALID_INCIDENT_STATUSES = {s.value for s in IncidentStatus}

_PRIORITY_TO_SEVERITY = {
    "p1": SeverityLevel.CRITICAL,
    "p2": SeverityLevel.HIGH,
    "p3": SeverityLevel.MEDIUM,
    "p4": SeverityLevel.LOW,
}


# ── Coercion helpers ─────────────────────────────────────────────────────────

def _enum_text(value: Any) -> str:
    """
    Normalise a value that may already be the enum we are coercing to.

    ``str()`` on a ``(str, Enum)`` member yields "SeverityLevel.HIGH" on Python ≤3.10
    and "high" on 3.11+, so an already-typed value round-tripped through here silently
    became the default on one interpreter and worked on the other.
    """
    if isinstance(value, PyEnum):
        value = value.value
    return str(value or "").strip().lower()


def coerce_severity(value: Any, default: SeverityLevel = SeverityLevel.MEDIUM) -> SeverityLevel:
    """Map free-form LLM severity text onto the SeverityLevel enum."""
    text = _enum_text(value)
    if text in _VALID_SEVERITIES:
        return SeverityLevel(text)
    return default


def coerce_incident_status(value: Any, default: IncidentStatus = IncidentStatus.OPEN) -> IncidentStatus:
    text = _enum_text(value)
    if text in _VALID_INCIDENT_STATUSES:
        return IncidentStatus(text)
    return default


def severity_from_cvss(score: float | None) -> SeverityLevel:
    """NVD CVSS v3 qualitative severity bands."""
    if score is None:
        return SeverityLevel.MEDIUM
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    if score > 0.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def _as_uuid(value: Any) -> uuid.UUID | None:
    """Accept an id that may be a UUID, a UUID string, or an arbitrary LLM label."""
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _clip(value: Any, length: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text[:length] if len(text) > length else text


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def enabled() -> bool:
    return bool(settings.enable_persistence)


# ── Threat events ────────────────────────────────────────────────────────────

async def save_threat_event(
    raw_event: dict,
    assessment: dict,
    enrichment: dict | None = None,
    incident_id: Any = None,
) -> str | None:
    """Persist one classified threat event. Returns the row id, or None on failure."""
    if not enabled():
        return None
    try:
        async with AsyncSessionLocal() as session:
            row = ThreatEvent(
                source_ip=_clip(raw_event.get("source_ip"), 45),
                destination_ip=_clip(raw_event.get("destination_ip"), 45),
                source_port=_to_int(raw_event.get("source_port")),
                destination_port=_to_int(raw_event.get("destination_port")),
                protocol=_clip(raw_event.get("protocol"), 20),
                threat_type=_clip(assessment.get("threat_type") or "unknown", 100),
                severity=coerce_severity(assessment.get("severity")),
                confidence_score=_to_float(assessment.get("confidence")) or 0.0,
                raw_log=raw_event.get("raw") or raw_event.get("message"),
                enrichment_data=enrichment or {},
                mitre_tactics=assessment.get("mitre_tactics") or [],
                mitre_techniques=assessment.get("mitre_techniques") or [],
                incident_id=_as_uuid(incident_id),
            )
            session.add(row)
            await session.commit()
            return str(row.id)
    except Exception as exc:
        log.warning("persistence.save_threat_event_failed", error=str(exc))
        return None


async def recent_threat_events(limit: int = 50, severity: str | None = None) -> list[dict]:
    if not enabled():
        return []
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(ThreatEvent).order_by(desc(ThreatEvent.created_at)).limit(limit)
            if severity:
                stmt = stmt.where(ThreatEvent.severity == coerce_severity(severity))
            rows = (await session.execute(stmt)).scalars().all()
            return [_threat_to_dict(r) for r in rows]
    except Exception as exc:
        log.warning("persistence.recent_threat_events_failed", error=str(exc))
        return []


def _threat_to_dict(row: ThreatEvent) -> dict:
    return {
        "id": str(row.id),
        "source_ip": row.source_ip,
        "destination_ip": row.destination_ip,
        "source_port": row.source_port,
        "destination_port": row.destination_port,
        "protocol": row.protocol,
        "threat_type": row.threat_type,
        "severity": row.severity.value if row.severity else None,
        "confidence_score": row.confidence_score,
        "raw_log": row.raw_log,
        "enrichment_data": row.enrichment_data,
        "mitre_tactics": row.mitre_tactics,
        "mitre_techniques": row.mitre_techniques,
        "is_false_positive": row.is_false_positive,
        "incident_id": str(row.incident_id) if row.incident_id else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def threat_severity_counts(hours: int = 24) -> dict[str, int]:
    """Severity histogram over the trailing window — powers the dashboard chart."""
    if not enabled():
        return {}
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(int(hours), 1))
    try:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(ThreatEvent.severity, func.count())
                .where(ThreatEvent.created_at >= cutoff)
                .group_by(ThreatEvent.severity)
            )
            rows = (await session.execute(stmt)).all()
            return {(sev.value if sev else "unknown"): int(count) for sev, count in rows}
    except Exception as exc:
        log.warning("persistence.threat_severity_counts_failed", error=str(exc))
        return {}


# ── Incidents ────────────────────────────────────────────────────────────────

async def save_incident(
    incident: dict,
    response_plan: dict,
    actions_taken: list[dict] | None = None,
) -> str | None:
    """Create (or update, when the id already exists) an incident record."""
    if not enabled():
        return None
    try:
        async with AsyncSessionLocal() as session:
            incident_uuid = _as_uuid(response_plan.get("incident_id")) or _as_uuid(incident.get("id"))
            row = None
            if incident_uuid:
                row = await session.get(Incident, incident_uuid)

            severity = coerce_severity(
                incident.get("severity"),
                default=_PRIORITY_TO_SEVERITY.get(
                    str(response_plan.get("priority", "")).lower(), SeverityLevel.MEDIUM
                ),
            )
            title = _clip(
                incident.get("title") or f"{response_plan.get('playbook', 'incident')} response",
                255,
            )

            if row is None:
                row = Incident(id=incident_uuid or uuid.uuid4())
                session.add(row)

            row.title = title
            row.description = incident.get("description") or ""
            row.severity = severity
            row.status = coerce_incident_status(incident.get("status"), IncidentStatus.INVESTIGATING)
            row.assigned_agent = "incident_response"
            row.playbook_used = _clip(response_plan.get("playbook") or incident.get("type"), 100)
            row.timeline = response_plan.get("timeline") or []
            row.remediation_steps = response_plan.get("containment_actions") or []
            row.affected_assets = (
                incident.get("affected_assets") or response_plan.get("affected_assets") or []
            )
            await session.commit()
            return str(row.id)
    except Exception as exc:
        log.warning("persistence.save_incident_failed", error=str(exc))
        return None


async def update_incident(incident_id: str, status: str, note: str | None = None) -> dict | None:
    if not enabled():
        return None
    incident_uuid = _as_uuid(incident_id)
    if incident_uuid is None:
        return None
    try:
        async with AsyncSessionLocal() as session:
            row = await session.get(Incident, incident_uuid)
            if row is None:
                return None
            row.status = coerce_incident_status(status, row.status)
            if row.status == IncidentStatus.RESOLVED and row.resolved_at is None:
                row.resolved_at = datetime.now(timezone.utc)
            if note:
                timeline = list(row.timeline or [])
                timeline.append({
                    "time": datetime.now(timezone.utc).isoformat(),
                    "event": note,
                })
                row.timeline = timeline
            await session.commit()
            return _incident_to_dict(row)
    except Exception as exc:
        log.warning("persistence.update_incident_failed", error=str(exc))
        return None


async def get_incident(incident_id: str) -> dict | None:
    if not enabled():
        return None
    incident_uuid = _as_uuid(incident_id)
    if incident_uuid is None:
        return None
    try:
        async with AsyncSessionLocal() as session:
            row = await session.get(Incident, incident_uuid)
            return _incident_to_dict(row) if row else None
    except Exception as exc:
        log.warning("persistence.get_incident_failed", error=str(exc))
        return None


async def list_incidents(limit: int = 20, status: str | None = None) -> list[dict]:
    if not enabled():
        return []
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(Incident).order_by(desc(Incident.created_at)).limit(limit)
            if status:
                stmt = stmt.where(Incident.status == coerce_incident_status(status))
            rows = (await session.execute(stmt)).scalars().all()
            return [_incident_to_dict(r) for r in rows]
    except Exception as exc:
        log.warning("persistence.list_incidents_failed", error=str(exc))
        return []


def _incident_to_dict(row: Incident) -> dict:
    return {
        "id": str(row.id),
        "title": row.title,
        "description": row.description,
        "severity": row.severity.value if row.severity else None,
        "status": row.status.value if row.status else None,
        "assigned_agent": row.assigned_agent,
        "playbook_used": row.playbook_used,
        "timeline": row.timeline,
        "remediation_steps": row.remediation_steps,
        "affected_assets": row.affected_assets,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ── Vulnerabilities ──────────────────────────────────────────────────────────

async def save_vulnerability(cve_data: dict, risk_report: dict) -> str | None:
    """Upsert a CVE record keyed on cve_id."""
    if not enabled():
        return None
    cve_id = _clip(cve_data.get("cve_id") or risk_report.get("cve_id"), 30)
    if not cve_id:
        return None
    try:
        async with AsyncSessionLocal() as session:
            existing = (
                await session.execute(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
            ).scalar_one_or_none()

            cvss = _to_float(cve_data.get("cvss_score"))
            affected = risk_report.get("affected_assets") or []
            row = existing or Vulnerability(cve_id=cve_id)
            row.title = _clip(risk_report.get("summary") or cve_id, 500)
            row.description = cve_data.get("description") or ""
            row.cvss_score = cvss
            row.cvss_vector = _clip(cve_data.get("vector"), 100)
            row.severity = coerce_severity(cve_data.get("severity"), severity_from_cvss(cvss))
            row.affected_products = affected
            row.patch_available = bool(risk_report.get("remediation"))
            row.exploit_available = str(risk_report.get("exploitability", "")).lower() == "high"
            row.asset_ip = _clip(affected[0], 45) if affected else None
            row.remediation_status = (
                "urgent" if str(risk_report.get("patch_urgency")) == "immediate" else "open"
            )
            if existing is None:
                session.add(row)
            await session.commit()
            return str(row.id)
    except Exception as exc:
        log.warning("persistence.save_vulnerability_failed", error=str(exc))
        return None


async def list_vulnerabilities(limit: int = 50) -> list[dict]:
    if not enabled():
        return []
    try:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(Vulnerability)
                .order_by(desc(Vulnerability.cvss_score), desc(Vulnerability.created_at))
                .limit(limit)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [
                {
                    "id": str(r.id),
                    "cve_id": r.cve_id,
                    "title": r.title,
                    "description": r.description,
                    "cvss_score": r.cvss_score,
                    "cvss_vector": r.cvss_vector,
                    "severity": r.severity.value if r.severity else None,
                    "affected_products": r.affected_products,
                    "patch_available": r.patch_available,
                    "exploit_available": r.exploit_available,
                    "asset_ip": r.asset_ip,
                    "remediation_status": r.remediation_status,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ]
    except Exception as exc:
        log.warning("persistence.list_vulnerabilities_failed", error=str(exc))
        return []


# ── Compliance ───────────────────────────────────────────────────────────────

async def save_compliance_results(framework: str, control_results: list[dict]) -> int:
    """Persist one row per evaluated control. Returns the number of rows written."""
    if not enabled() or not control_results:
        return 0
    try:
        async with AsyncSessionLocal() as session:
            for result in control_results:
                session.add(ComplianceCheck(
                    framework=_clip(framework, 50) or "unknown",
                    control_id=_clip(result.get("control_id") or "unknown", 50),
                    control_name=_clip(result.get("control_name") or "", 255) or "",
                    status=_clip(result.get("status") or "partial", 50),
                    evidence=result.get("remediation") or "",
                    findings=result.get("findings") or [],
                ))
            await session.commit()
            return len(control_results)
    except Exception as exc:
        log.warning("persistence.save_compliance_results_failed", error=str(exc))
        return 0


async def compliance_history(framework: str | None = None, limit: int = 100) -> list[dict]:
    if not enabled():
        return []
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(ComplianceCheck).order_by(desc(ComplianceCheck.created_at)).limit(limit)
            if framework:
                stmt = stmt.where(ComplianceCheck.framework == framework)
            rows = (await session.execute(stmt)).scalars().all()
            return [
                {
                    "id": str(r.id),
                    "framework": r.framework,
                    "control_id": r.control_id,
                    "control_name": r.control_name,
                    "status": r.status,
                    "evidence": r.evidence,
                    "findings": r.findings,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ]
    except Exception as exc:
        log.warning("persistence.compliance_history_failed", error=str(exc))
        return []


# ── Agent audit log / registry ───────────────────────────────────────────────

async def save_agent_action(
    agent_name: str,
    action_type: str,
    description: str = "",
    input_data: dict | None = None,
    output_data: dict | None = None,
    success: bool = True,
    duration_ms: int | None = None,
) -> str | None:
    if not enabled():
        return None
    try:
        async with AsyncSessionLocal() as session:
            row = AgentAction(
                agent_name=_clip(agent_name, 100) or "unknown",
                action_type=_clip(action_type, 100) or "run",
                description=description,
                input_data=_jsonable(input_data),
                output_data=_jsonable(output_data),
                success=success,
                duration_ms=duration_ms,
            )
            session.add(row)
            await session.commit()
            return str(row.id)
    except Exception as exc:
        log.warning("persistence.save_agent_action_failed", error=str(exc))
        return None


def _jsonable(data: dict | None) -> dict | None:
    """Keep the audit payload JSON-serialisable and bounded in size."""
    if data is None:
        return None
    import json
    try:
        text = json.dumps(data, default=str)
    except Exception:
        return {"repr": str(data)[:4000]}
    if len(text) > 8000:
        return {"truncated": True, "preview": text[:8000]}
    return json.loads(text)


async def record_agent_heartbeat(
    agent_name: str,
    status: str,
    current_task: str | None = None,
    completed: bool = False,
    failed: bool = False,
) -> None:
    """Upsert the agent registry row used by /agents/status and the Grafana panels."""
    if not enabled():
        return
    try:
        async with AsyncSessionLocal() as session:
            row = (
                await session.execute(
                    select(AgentRegistry).where(AgentRegistry.agent_name == agent_name)
                )
            ).scalar_one_or_none()
            if row is None:
                row = AgentRegistry(agent_name=_clip(agent_name, 100), agent_type="langgraph")
                session.add(row)
            try:
                row.status = AgentStatus(str(status).lower())
            except ValueError:
                row.status = AgentStatus.IDLE
            row.last_heartbeat = datetime.now(timezone.utc)
            row.current_task = _clip(current_task, 255)
            if completed:
                row.tasks_completed = (row.tasks_completed or 0) + 1
            if failed:
                row.tasks_failed = (row.tasks_failed or 0) + 1
            await session.commit()
    except Exception as exc:
        log.warning("persistence.record_agent_heartbeat_failed", error=str(exc))


async def list_agent_registry() -> list[dict]:
    if not enabled():
        return []
    try:
        async with AsyncSessionLocal() as session:
            rows = (await session.execute(select(AgentRegistry))).scalars().all()
            return [
                {
                    "agent_name": r.agent_name,
                    "agent_type": r.agent_type,
                    "status": r.status.value if r.status else None,
                    "last_heartbeat": r.last_heartbeat.isoformat() if r.last_heartbeat else None,
                    "tasks_completed": r.tasks_completed,
                    "tasks_failed": r.tasks_failed,
                    "current_task": r.current_task,
                }
                for r in rows
            ]
    except Exception as exc:
        log.warning("persistence.list_agent_registry_failed", error=str(exc))
        return []


# ── Log entries ──────────────────────────────────────────────────────────────

async def save_log_entries(
    logs: list[dict],
    anomaly_indices: dict[int, dict] | None = None,
    es_index: str | None = None,
) -> int:
    """
    Persist an analysed log batch. ``anomaly_indices`` maps a batch position to the
    anomaly the log-analysis agent found there, so the row is flagged accordingly.
    """
    if not enabled() or not logs:
        return 0
    anomaly_indices = anomaly_indices or {}
    severity_score = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
    written = 0
    try:
        async with AsyncSessionLocal() as session:
            for i, entry in enumerate(logs):
                if not isinstance(entry, dict):
                    continue
                written += 1
                anomaly = anomaly_indices.get(i)
                session.add(LogEntry(
                    source=_clip(entry.get("source") or "unknown", 100) or "unknown",
                    log_level=_clip(entry.get("log_level") or "INFO", 20) or "INFO",
                    message=str(entry.get("message") or ""),
                    host=_clip(entry.get("host"), 255),
                    service=_clip(entry.get("service"), 100),
                    parsed_fields=entry.get("parsed_fields") or {},
                    anomaly_score=(
                        severity_score.get(str(anomaly.get("severity", "")).lower(), 0.5)
                        if anomaly else 0.0
                    ),
                    is_anomalous=anomaly is not None,
                    es_index=_clip(es_index, 100),
                ))
            await session.commit()
            # Count rows actually added, not entries offered: a batch containing
            # non-dict junk used to report every entry as stored, and the dashboard
            # showed "Stored 20 rows" for a batch that wrote 3.
            return written
    except Exception as exc:
        log.warning("persistence.save_log_entries_failed", error=str(exc))
        return 0


async def count_open_incidents() -> int:
    if not enabled():
        return 0
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(func.count()).select_from(Incident).where(
                Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING])
            )
            return int((await session.execute(stmt)).scalar() or 0)
    except Exception as exc:
        log.warning("persistence.count_open_incidents_failed", error=str(exc))
        return 0
