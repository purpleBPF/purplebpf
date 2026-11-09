"""create review_decisions

Revision ID: a7c3f9b2e641
Revises: 19e52059372d
Create Date: 2026-11-09

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "a7c3f9b2e641"
down_revision: Union[str, None] = "19e52059372d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 2차 검수(사람 승인/반려) 결정을 영속화하는 테이블.
    # 검증기(RULE_VALIDATOR) 또는 1차 필터(FIRST_FILTER)가 체인을 REVIEW로
    # 막으면 PENDING 행이 1건 생기고, Slack 버튼 클릭 콜백이 그 행을
    # APPROVED/REJECTED로 갱신한다. chain_json에는 "차단된 체인 전체"를 담아,
    # 승인 시 재실행(워크스트림 C)이 이 행만 보고도 체인을 복원할 수 있게 한다.
    op.create_table(
        "review_decisions",
        sa.Column(
            "review_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("technique_id", sa.Text(), nullable=False),
        # 라운드 밖(수동 검수 등)에서 올라온 검수건은 round_id가 없을 수 있다.
        sa.Column("round_id", sa.Integer(), nullable=True),
        sa.Column("source", sa.Text(), nullable=False),
        # 차단된 체인 전체(goal/steps 포함). C가 재실행 입력으로 그대로 소비한다.
        sa.Column("chain_json", postgresql.JSONB(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'PENDING'"),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # 결정 전에는 NULL. 버튼을 누른 Slack 사용자 이름과 결정 시각을 남긴다.
        sa.Column("decided_by", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "source IN ('RULE_VALIDATOR', 'FIRST_FILTER')",
            name="ck_review_decisions_source",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'APPROVED', 'REJECTED')",
            name="ck_review_decisions_status",
        ),
    )

    # 승인 대기/승인 집계(list_approved_pending_execution)와 기법별 조회용 인덱스.
    op.create_index("ix_review_decisions_status", "review_decisions", ["status"])
    op.create_index(
        "ix_review_decisions_technique_id", "review_decisions", ["technique_id"]
    )
    op.create_index("ix_review_decisions_created_at", "review_decisions", ["created_at"])


def downgrade() -> None:
    op.drop_table("review_decisions")
