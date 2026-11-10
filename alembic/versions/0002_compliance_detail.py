"""Keep the full compliance verdict per control

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-10

0001 stored only status/findings, and the repository wrote the remediation text into
the `evidence` column — so a historical evaluation could not reproduce its score, its
risk rating or the evidence it was judged on, and rows from different runs could not
be told apart.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("compliance_checks", sa.Column("score", sa.Float))
    op.add_column("compliance_checks", sa.Column("risk_if_failed", sa.String(20)))
    op.add_column("compliance_checks", sa.Column("evidence_quality", sa.String(20)))
    op.add_column("compliance_checks", sa.Column("remediation", sa.Text))
    op.add_column("compliance_checks", sa.Column("evaluation_id", UUID(as_uuid=True)))
    op.create_index(
        "ix_compliance_checks_evaluation_id", "compliance_checks", ["evaluation_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_compliance_checks_evaluation_id", table_name="compliance_checks")
    for column in ("evaluation_id", "remediation", "evidence_quality", "risk_if_failed", "score"):
        op.drop_column("compliance_checks", column)
