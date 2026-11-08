"""create snapshots

Revision ID: a3f9c2d17b4e
Revises: 19e52059372d
Create Date: 2026-11-08

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "a3f9c2d17b4e"
down_revision: Union[str, None] = "19e52059372d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "snapshots",
        sa.Column("snapshot_id", sa.BigInteger(), primary_key=True, autoincrement=True),
        # detections와 같이 물리적 FK 없이 run_id로 execution_log와 논리적으로 연결한다.
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("fs_diff", postgresql.JSONB(), nullable=True),
        sa.Column("processes", postgresql.JSONB(), nullable=True),
        sa.Column("net_conns", postgresql.JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("captured_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('ok', 'partial', 'failed')",
            name="ck_snapshots_status",
        ),
        sa.UniqueConstraint("run_id", name="uq_snapshots_run_id"),
    )


def downgrade() -> None:
    op.drop_table("snapshots")