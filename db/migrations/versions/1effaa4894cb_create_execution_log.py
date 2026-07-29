"""create execution_log

Revision ID: 1effaa4894cb
Revises:
Create Date: 2026-07-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "1effaa4894cb"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "execution_log",
        sa.Column("run_id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("round_id", sa.Integer(), nullable=False),
        sa.Column("chain_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("technique", sa.String(length=16), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("container_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "channel IN ('syscall', 'io_uring')",
            name="ck_execution_log_channel",
        ),
        sa.CheckConstraint(
            r"technique ~ '^T[0-9]{4}(\.[0-9]{3})?$'",
            name="ck_execution_log_technique",
        ),
    )

    op.create_index("ix_execution_log_round_id", "execution_log", ["round_id"])
    op.create_index(
        "ix_execution_log_run_id_technique_channel",
        "execution_log",
        ["run_id", "technique", "channel"],
    )
    op.create_index("ix_execution_log_started_at", "execution_log", ["started_at"])
    op.create_index(
        "ix_execution_log_container_id_started_at",
        "execution_log",
        ["container_id", "started_at"],
    )


def downgrade() -> None:
    op.drop_table("execution_log")
