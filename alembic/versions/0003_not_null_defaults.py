"""Enforce NOT NULL where the application always supplies a value

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-10

0001 created these columns nullable while the ORM models declare them required (and
always write a value or rely on the server default). Backfill any stray NULLs with
the column's default, then enforce the constraint so the database and the models
describe the same schema.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TIMESTAMPED = (
    "incidents", "threat_events", "vulnerabilities", "compliance_checks",
    "agent_registry", "agent_actions", "log_entries",
)

# (table, column, backfill SQL expression)
REQUIRED = [
    *[(t, c, "now()") for t in TIMESTAMPED for c in ("created_at", "updated_at")],
    ("threat_events", "confidence_score", "0.0"),
    ("threat_events", "is_false_positive", "false"),
    ("vulnerabilities", "patch_available", "false"),
    ("vulnerabilities", "exploit_available", "false"),
    ("vulnerabilities", "remediation_status", "'open'"),
    ("agent_registry", "tasks_completed", "0"),
    ("agent_registry", "tasks_failed", "0"),
    ("agent_actions", "success", "true"),
    ("log_entries", "is_anomalous", "false"),
]


def upgrade() -> None:
    for table, column, default in REQUIRED:
        op.execute(f"UPDATE {table} SET {column} = {default} WHERE {column} IS NULL")
        op.alter_column(table, column, nullable=False)


def downgrade() -> None:
    for table, column, _ in reversed(REQUIRED):
        op.alter_column(table, column, nullable=True)
