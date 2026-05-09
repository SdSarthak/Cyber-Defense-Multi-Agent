"""Initial schema — all tables

Revision ID: 0001
Revises:
Create Date: 2026-05-08
"""
from typing import Sequence, Union
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    op.create_table(
        "incidents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(50), nullable=False, server_default="open"),
        sa.Column("assigned_agent", sa.String(100)),
        sa.Column("playbook_used", sa.String(100)),
        sa.Column("timeline", JSON),
        sa.Column("remediation_steps", JSON),
        sa.Column("affected_assets", JSON),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])

    op.create_table(
        "threat_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("destination_ip", sa.String(45)),
        sa.Column("source_port", sa.Integer),
        sa.Column("destination_port", sa.Integer),
        sa.Column("protocol", sa.String(20)),
        sa.Column("threat_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("confidence_score", sa.Float, server_default="0.0"),
        sa.Column("raw_log", sa.Text),
        sa.Column("enrichment_data", JSON),
        sa.Column("mitre_tactics", JSON),
        sa.Column("mitre_techniques", JSON),
        sa.Column("is_false_positive", sa.Boolean, server_default="false"),
        sa.Column("incident_id", UUID(as_uuid=True), sa.ForeignKey("incidents.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_threat_events_severity", "threat_events", ["severity"])
    op.create_index("ix_threat_events_source_ip", "threat_events", ["source_ip"])
    op.create_index("ix_threat_events_created_at", "threat_events", ["created_at"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("cve_id", sa.String(30), unique=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("cvss_score", sa.Float),
        sa.Column("cvss_vector", sa.String(100)),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("affected_products", JSON),
        sa.Column("patch_available", sa.Boolean, server_default="false"),
        sa.Column("patch_url", sa.Text),
        sa.Column("exploit_available", sa.Boolean, server_default="false"),
        sa.Column("asset_ip", sa.String(45)),
        sa.Column("remediation_status", sa.String(50), server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])

    op.create_table(
        "compliance_checks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("framework", sa.String(50), nullable=False),
        sa.Column("control_id", sa.String(50), nullable=False),
        sa.Column("control_name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("evidence", sa.Text),
        sa.Column("findings", JSON),
        sa.Column("next_review", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_compliance_framework", "compliance_checks", ["framework"])
    op.create_index("ix_compliance_status", "compliance_checks", ["status"])

    op.create_table(
        "agent_registry",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("agent_name", sa.String(100), unique=True, nullable=False),
        sa.Column("agent_type", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="idle"),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True)),
        sa.Column("tasks_completed", sa.Integer, server_default="0"),
        sa.Column("tasks_failed", sa.Integer, server_default="0"),
        sa.Column("current_task", sa.String(255)),
        sa.Column("config", JSON),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_agent_registry_agent_name", "agent_registry", ["agent_name"])

    op.create_table(
        "agent_actions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("agent_name", sa.String(100), nullable=False),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("input_data", JSON),
        sa.Column("output_data", JSON),
        sa.Column("success", sa.Boolean, server_default="true"),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("incident_id", UUID(as_uuid=True), sa.ForeignKey("incidents.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_agent_actions_agent_name", "agent_actions", ["agent_name"])

    op.create_table(
        "log_entries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("log_level", sa.String(20), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("host", sa.String(255)),
        sa.Column("service", sa.String(100)),
        sa.Column("parsed_fields", JSON),
        sa.Column("anomaly_score", sa.Float),
        sa.Column("is_anomalous", sa.Boolean, server_default="false"),
        sa.Column("es_index", sa.String(100)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_log_entries_source", "log_entries", ["source"])
    op.create_index("ix_log_entries_is_anomalous", "log_entries", ["is_anomalous"])

    # Seed default agent registry entries
    op.execute("""
        INSERT INTO agent_registry (id, agent_name, agent_type, status) VALUES
        (uuid_generate_v4(), 'threat_detection',   'ThreatDetectionAgent',      'idle'),
        (uuid_generate_v4(), 'log_analysis',        'LogAnalysisAgent',           'idle'),
        (uuid_generate_v4(), 'vulnerability_intel', 'VulnerabilityIntelAgent',    'idle'),
        (uuid_generate_v4(), 'incident_response',   'IncidentResponseAgent',      'idle'),
        (uuid_generate_v4(), 'compliance',          'ComplianceAgent',            'idle'),
        (uuid_generate_v4(), 'reporting',           'ReportingAgent',             'idle'),
        (uuid_generate_v4(), 'supervisor',          'SupervisorAgent',            'idle')
        ON CONFLICT (agent_name) DO NOTHING
    """)


def downgrade() -> None:
    op.drop_table("log_entries")
    op.drop_table("agent_actions")
    op.drop_table("agent_registry")
    op.drop_table("compliance_checks")
    op.drop_table("vulnerabilities")
    op.drop_table("threat_events")
    op.drop_table("incidents")
