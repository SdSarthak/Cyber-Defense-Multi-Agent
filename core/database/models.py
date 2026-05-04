import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    String, Text, Float, Boolean, Integer, JSON,
    ForeignKey, Enum, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from core.database.base import Base, TimestampMixin


class SeverityLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, PyEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AgentStatus(str, PyEnum):
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    DISABLED = "disabled"


# ── Threat Events ─────────────────────────────────────────────────────────────

class ThreatEvent(Base, TimestampMixin):
    __tablename__ = "threat_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(20))
    threat_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    raw_log: Mapped[str | None] = mapped_column(Text)
    enrichment_data: Mapped[dict | None] = mapped_column(JSON)
    mitre_tactics: Mapped[list | None] = mapped_column(JSON)
    mitre_techniques: Mapped[list | None] = mapped_column(JSON)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"))

    incident: Mapped["Incident | None"] = relationship("Incident", back_populates="threat_events")

    __table_args__ = (
        Index("ix_threat_events_severity", "severity"),
        Index("ix_threat_events_source_ip", "source_ip"),
        Index("ix_threat_events_created_at", "created_at"),
    )


# ── Incidents ─────────────────────────────────────────────────────────────────

class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    assigned_agent: Mapped[str | None] = mapped_column(String(100))
    playbook_used: Mapped[str | None] = mapped_column(String(100))
    timeline: Mapped[list | None] = mapped_column(JSON)
    remediation_steps: Mapped[list | None] = mapped_column(JSON)
    affected_assets: Mapped[list | None] = mapped_column(JSON)
    resolved_at: Mapped[datetime | None] = mapped_column()

    threat_events: Mapped[list["ThreatEvent"]] = relationship("ThreatEvent", back_populates="incident")
    agent_actions: Mapped[list["AgentAction"]] = relationship("AgentAction", back_populates="incident")

    __table_args__ = (
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity"),
    )


# ── Vulnerabilities ───────────────────────────────────────────────────────────

class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str | None] = mapped_column(String(30), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(100))
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    affected_products: Mapped[list | None] = mapped_column(JSON)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_url: Mapped[str | None] = mapped_column(Text)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    asset_ip: Mapped[str | None] = mapped_column(String(45))
    remediation_status: Mapped[str] = mapped_column(String(50), default="open")


# ── Compliance ────────────────────────────────────────────────────────────────

class ComplianceCheck(Base, TimestampMixin):
    __tablename__ = "compliance_checks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework: Mapped[str] = mapped_column(String(50))   # e.g. SOC2, ISO27001, NIST
    control_id: Mapped[str] = mapped_column(String(50))
    control_name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(50))      # pass, fail, partial, na
    evidence: Mapped[str | None] = mapped_column(Text)
    findings: Mapped[list | None] = mapped_column(JSON)
    next_review: Mapped[datetime | None] = mapped_column()

    __table_args__ = (
        Index("ix_compliance_framework", "framework"),
        Index("ix_compliance_status", "status"),
    )


# ── Agent Registry ────────────────────────────────────────────────────────────

class AgentRegistry(Base, TimestampMixin):
    __tablename__ = "agent_registry"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    agent_type: Mapped[str] = mapped_column(String(100))
    status: Mapped[AgentStatus] = mapped_column(Enum(AgentStatus), default=AgentStatus.IDLE)
    last_heartbeat: Mapped[datetime | None] = mapped_column()
    tasks_completed: Mapped[int] = mapped_column(Integer, default=0)
    tasks_failed: Mapped[int] = mapped_column(Integer, default=0)
    current_task: Mapped[str | None] = mapped_column(String(255))
    config: Mapped[dict | None] = mapped_column(JSON)


# ── Agent Actions (audit log) ─────────────────────────────────────────────────

class AgentAction(Base, TimestampMixin):
    __tablename__ = "agent_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_name: Mapped[str] = mapped_column(String(100), index=True)
    action_type: Mapped[str] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text)
    input_data: Mapped[dict | None] = mapped_column(JSON)
    output_data: Mapped[dict | None] = mapped_column(JSON)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"))

    incident: Mapped["Incident | None"] = relationship("Incident", back_populates="agent_actions")

    __table_args__ = (Index("ix_agent_actions_agent_name", "agent_name"),)


# ── Log Entries ───────────────────────────────────────────────────────────────

class LogEntry(Base, TimestampMixin):
    __tablename__ = "log_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(100), index=True)
    log_level: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(String(255))
    service: Mapped[str | None] = mapped_column(String(100))
    parsed_fields: Mapped[dict | None] = mapped_column(JSON)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False)
    es_index: Mapped[str | None] = mapped_column(String(100))

    __table_args__ = (
        Index("ix_log_entries_source", "source"),
        Index("ix_log_entries_is_anomalous", "is_anomalous"),
    )
