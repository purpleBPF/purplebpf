"""create detections

Revision ID: 19e52059372d
Revises: 1effaa4894cb
Create Date: 2026-08-05 10:03:27.988936

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '19e52059372d'
down_revision: Union[str, None] = '1effaa4894cb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detections",
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # 물리적 FK를 걸지 않는다: run_id는 execution_log와 논리적으로만 연결되며,
        # FP(오탐)는 매칭되는 실행이 없어 NULL을 허용해야 한다.
        sa.Column("run_id", sa.BigInteger(), nullable=True),
        sa.Column("round_id", sa.Integer(), nullable=True),
        sa.Column("technique", sa.String(length=16), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("rule_name", sa.String(length=128), nullable=False),
        sa.Column("detected_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("container_id", sa.String(length=64), nullable=True),
        sa.Column("binary_path", sa.String(length=256), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "channel IN ('syscall', 'io_uring')",
            name="ck_detections_channel",
        ),
    )

    op.create_index("ix_detections_run_id", "detections", ["run_id"])
    op.create_index(
        "ix_detections_run_id_technique_channel",
        "detections",
        ["run_id", "technique", "channel"],
    )
    op.create_index("ix_detections_detected_at", "detections", ["detected_at"])
    op.create_index("ix_detections_rule_name", "detections", ["rule_name"])


def downgrade() -> None:
    op.drop_table("detections")
