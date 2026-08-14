"""정상 워크로드 실행 기록 테이블

오탐을 재려면 공격이 아닌 실행 기록이 필요하다. execution_log 에 넣을 수는
없다. technique 컬럼이 nullable=False 이고 형식 제약이 걸려 있어
ATT&CK 번호만 들어간다.

    technique ~ '^T[0-9]{4}(\\.[0-9]{3})?$'

BENIGN 같은 값도 NULL 도 안 들어가므로 별도 테이블을 둔다. 컬럼 구성은
execution_log 와 맞췄다. 조인 조건을 그대로 재사용하기 위해서다.

kind 는 두 가지다.
  normal  평범한 정상 동작. 어느 규칙도 안 뜨는 것이 정상
  trap    공격과 겉모습이 비슷하지만 정상인 것.
          규칙이 제대로 좁혀졌는지 시험한다

Revision ID: 2a1c4f7b9d30
Revises: 19e52059372d
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "2a1c4f7b9d30"
down_revision: Union[str, None] = "19e52059372d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "benign_log",
        sa.Column("run_id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("round_id", sa.Integer(), nullable=False),
        sa.Column("chain_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        # 공격의 technique 자리. 소문자와 밑줄만 쓴다.
        sa.Column("label", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("container_id", sa.String(length=64), nullable=False),
        # 이 워크로드에서 뜨면 안 되는 규칙 이름. 여기 있는 규칙이 뜨면 오탐이다.
        sa.Column("expect_silent", sa.dialects.postgresql.ARRAY(sa.Text()), nullable=False,
                  server_default="{}"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint("kind IN ('normal', 'trap')", name="ck_benign_log_kind"),
    )
    op.create_index("ix_benign_log_round", "benign_log", ["round_id"])
    op.create_index("ix_benign_log_container", "benign_log", ["container_id"])


def downgrade() -> None:
    op.drop_index("ix_benign_log_container", table_name="benign_log")
    op.drop_index("ix_benign_log_round", table_name="benign_log")
    op.drop_table("benign_log")
