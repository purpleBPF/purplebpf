"""2차 검수 결정의 영속화 헬퍼.

검증기/1차 필터가 체인을 REVIEW로 막으면 PENDING 행을 1건 만들고
(`create_pending_review`), Slack 버튼 콜백이 그 행을 APPROVED/REJECTED로
갱신한다(`record_decision`). 승인된 체인의 재실행(워크스트림 C)은
`list_approved_pending_execution`으로 대기열을 읽고 `get_review`로 체인 전체를
복원한다.

[설계 메모]
- 레포의 다른 DB 접근(executor._insert_execution_log)과 같이 SQLAlchemy 엔진을
  받아 쓰되, 여기서는 Core 표현식을 쓴다. 테스트가 Postgres 없이 sqlite 엔진으로
  동일 코드를 돌릴 수 있도록 dialect 중립 타입(String/JSON)으로 테이블을 정의한다.
  실제 운영 스키마(JSONB/UUID)는 Alembic 마이그레이션이 만든다 — 이 모듈의 Table
  정의는 질의 구성을 위한 것이며 운영 컬럼과 타입 호환된다.
- review_id는 서버 기본값(gen_random_uuid())에 의존하지 않고 파이썬에서 uuid4로
  생성해 명시적으로 넣는다(두 dialect 모두 호환, 삽입 직후 식별자 확정).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import sqlalchemy as sa
from sqlalchemy import Engine

from purplebpf.common.config import build_db_engine

STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
_DECIDED_STATUSES = frozenset({STATUS_APPROVED, STATUS_REJECTED})

SOURCE_RULE_VALIDATOR = "RULE_VALIDATOR"
SOURCE_FIRST_FILTER = "FIRST_FILTER"

# 운영 테이블(review_decisions)과 동일한 컬럼 구성. dialect 중립 타입을 써서
# sqlite 테스트에서도 metadata.create_all()로 동일 스키마를 만들 수 있게 한다.
metadata = sa.MetaData()
review_decisions = sa.Table(
    "review_decisions",
    metadata,
    sa.Column("review_id", sa.String(length=36), primary_key=True),
    sa.Column("technique_id", sa.Text(), nullable=False),
    sa.Column("round_id", sa.Integer(), nullable=True),
    sa.Column("source", sa.Text(), nullable=False),
    sa.Column("chain_json", sa.JSON(), nullable=False),
    sa.Column("status", sa.Text(), nullable=False),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("decided_by", sa.Text(), nullable=True),
    sa.Column("decided_at", sa.TIMESTAMP(timezone=True), nullable=True),
)


def create_all(engine: Engine) -> None:
    """테스트용: sqlite 등 빈 엔진에 review_decisions 테이블을 만든다.

    운영에서는 Alembic 마이그레이션이 테이블을 만들므로 호출하지 않는다.
    """
    metadata.create_all(engine, tables=[review_decisions])


def _engine(engine: Optional[Engine]) -> Engine:
    return engine if engine is not None else build_db_engine()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_dict(row) -> dict:
    return dict(row._mapping)


def create_pending_review(
    *,
    technique_id: str,
    round_id: Optional[int],
    source: str,
    chain_json: dict,
    engine: Optional[Engine] = None,
) -> str:
    """차단된 체인에 대한 PENDING 검수건을 1건 삽입하고 review_id를 돌려준다.

    review_id는 Slack 버튼 value로 쓰이며, 이후 결정(record_decision)과 재실행
    (C)이 모두 이 id로 행을 찾는다.
    """
    if source not in (SOURCE_RULE_VALIDATOR, SOURCE_FIRST_FILTER):
        raise ValueError(f"알 수 없는 source: {source!r}")

    review_id = str(uuid.uuid4())
    eng = _engine(engine)
    with eng.begin() as conn:
        conn.execute(
            sa.insert(review_decisions).values(
                review_id=review_id,
                technique_id=technique_id,
                round_id=round_id,
                source=source,
                chain_json=chain_json,
                status=STATUS_PENDING,
                created_at=_now(),
                decided_by=None,
                decided_at=None,
            )
        )
    return review_id


def record_decision(
    review_id: str,
    status: str,
    decided_by: Optional[str],
    engine: Optional[Engine] = None,
) -> Optional[dict]:
    """검수건을 APPROVED/REJECTED로 전이한다.

    갱신된 행을 dict로 돌려주고, 해당 review_id가 없으면 None을 돌려준다.
    (실행 연결·멱등 전이는 워크스트림 C의 책임이므로 여기서는 결정만 기록한다.)
    """
    if status not in _DECIDED_STATUSES:
        raise ValueError(
            f"record_decision의 status는 {sorted(_DECIDED_STATUSES)} 중 하나여야 한다: {status!r}"
        )

    eng = _engine(engine)
    with eng.begin() as conn:
        conn.execute(
            sa.update(review_decisions)
            .where(review_decisions.c.review_id == review_id)
            .values(status=status, decided_by=decided_by, decided_at=_now())
        )
    return get_review(review_id, engine=eng)


def get_review(review_id: str, engine: Optional[Engine] = None) -> Optional[dict]:
    """review_id로 검수건 1건을 조회한다. 없으면 None."""
    eng = _engine(engine)
    with eng.connect() as conn:
        row = conn.execute(
            sa.select(review_decisions).where(
                review_decisions.c.review_id == review_id
            )
        ).one_or_none()
    return _row_to_dict(row) if row is not None else None


def list_approved_pending_execution(engine: Optional[Engine] = None) -> list[dict]:
    """APPROVED 상태(= 승인됐으나 아직 실행 연결 전) 검수건을 오래된 순으로 반환.

    워크스트림 C가 이 목록을 폴링해 재실행 대상을 집는다. C가 실행을 끝낸 건은
    별도 상태(예: EXECUTED)로 전이시켜 이 목록에서 빠지게 할 수 있다.
    """
    eng = _engine(engine)
    with eng.connect() as conn:
        rows = conn.execute(
            sa.select(review_decisions)
            .where(review_decisions.c.status == STATUS_APPROVED)
            .order_by(review_decisions.c.created_at.asc())
        ).all()
    return [_row_to_dict(row) for row in rows]
