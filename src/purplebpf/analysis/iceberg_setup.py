"""Postgres의 detections 테이블을 로컬 Iceberg 테이블로 이관한다.

로컬 프로토타입용으로 서버 없는 구성을 쓴다: SQLite 카탈로그 + 로컬 파일시스템
웨어하우스(Parquet). execution_log는 Postgres에 그대로 남기고 이관하지 않는다.

라운드 단위 스냅샷 관리:
    detections 테이블을 round_id로 파티셔닝하고, 라운드마다 Iceberg 스냅샷
    레퍼런스(태그) `round-<round_id>`를 만들어 둔다. 태그는 해당 라운드를
    기록한 시점의 테이블 상태를 가리키므로, 나중에 그 라운드의 상태를
    타임트래블로 다시 읽을 수 있다(dbt_plugins.iceberg_plugin의 round_tag 참고).

멱등성:
    - migrate(): 실행할 때마다 Postgres의 현재 상태로 전체 overwrite한다.
      여러 번 실행해도 중복이 생기지 않는다(기존 동작 유지).
    - sync_round(round_id): 해당 라운드 파티션만 overwrite한다. 같은 라운드를
      다시 동기화해도 그 라운드의 행이 중복되지 않는다.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import pyarrow as pa
from pyiceberg.catalog.sql import SqlCatalog
from pyiceberg.expressions import EqualTo
from pyiceberg.table import Table
from pyiceberg.transforms import IdentityTransform
from sqlalchemy import text

from purplebpf.common.config import build_db_engine

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG_DB_PATH = REPO_ROOT / "data" / "iceberg" / "catalog.db"
WAREHOUSE_PATH = REPO_ROOT / "data" / "iceberg" / "warehouse"

CATALOG_NAME = "purplebpf"
NAMESPACE = "purplebpf"
TABLE_NAME = "detections"
TABLE_IDENTIFIER = f"{NAMESPACE}.{TABLE_NAME}"

# 라운드 파티션/태그 관련 상수.
# 파티션 필드 이름은 round_id와 겹치지 않게 round_part로 둔다(pyiceberg는 파티션
# 필드 이름이 소스 컬럼 이름과 같으면 충돌로 간주해 거부한다).
PARTITION_COLUMN = "round_id"
PARTITION_FIELD_NAME = "round_part"
# 태그 네이밍 규칙: round-<round_id> (예: round-7). C/D 워크스트림도 이 규칙에 맞춘다.
TAG_PREFIX = "round-"
# 보존(expire) 기본값: 태그가 달린 라운드 스냅샷은 항상 보호되고, 그 외 태그 없는
# 스냅샷 중 최신 N개를 추가로 남긴다.
DEFAULT_KEEP_RECENT = 5

# Postgres detections와 동일한 컬럼. UUID -> string, timestamptz -> timestamp(tz 없음)로 변환한다.
ICEBERG_SCHEMA = pa.schema(
    [
        pa.field("detection_id", pa.string(), nullable=False),
        pa.field("run_id", pa.int64(), nullable=True),
        pa.field("round_id", pa.int32(), nullable=True),
        pa.field("technique", pa.string(), nullable=False),
        pa.field("channel", pa.string(), nullable=False),
        pa.field("rule_name", pa.string(), nullable=False),
        pa.field("detected_at", pa.timestamp("us"), nullable=False),
        pa.field("container_id", pa.string(), nullable=True),
        pa.field("binary_path", pa.string(), nullable=True),
        pa.field("created_at", pa.timestamp("us"), nullable=False),
    ]
)

SELECT_DETECTIONS = text(
    """
    SELECT detection_id, run_id, round_id, technique, channel, rule_name,
           detected_at, container_id, binary_path, created_at
    FROM detections
    """
)

# 특정 라운드만 읽을 때 쓰는 쿼리. sync_round()에서 해당 라운드 파티션만
# overwrite하기 위해 사용한다.
SELECT_DETECTIONS_BY_ROUND = text(
    """
    SELECT detection_id, run_id, round_id, technique, channel, rule_name,
           detected_at, container_id, binary_path, created_at
    FROM detections
    WHERE round_id = :round_id
    """
)


def round_tag(round_id: int) -> str:
    """라운드 ID를 Iceberg 태그 이름으로 변환한다(round-<round_id>)."""
    return f"{TAG_PREFIX}{round_id}"


def migrate() -> int:
    """Postgres detections 전체를 Iceberg로 전체 교체(overwrite)한다.

    기존 동작을 유지한다: 재실행해도 중복이 생기지 않는다. 더해서, 이관된
    데이터에 존재하는 모든 라운드에 대해 현재 스냅샷을 가리키는 태그를
    만들어/갱신해 둔다.
    """
    catalog = build_catalog()
    table = get_or_create_table(catalog)

    arrow_table = _read_detections_from_postgres()
    snapshot_id = write_full(table, arrow_table)

    row_count = arrow_table.num_rows
    print(f"이관 완료: {row_count}행 (스냅샷 {snapshot_id})")

    verified_count = _count_rows(catalog)
    print(f"검증: Iceberg detections 테이블 스캔 결과 {verified_count}행")

    return row_count


def sync_round(round_id: int) -> int:
    """특정 라운드의 detections만 Iceberg에 반영하고 태그를 찍는다.

    해당 라운드 파티션만 overwrite하므로, 같은 라운드를 다시 동기화해도
    그 라운드의 행이 중복되지 않는다(멱등). 반영 후 round-<round_id> 태그를
    현재 스냅샷에 생성/갱신한다.
    """
    catalog = build_catalog()
    table = get_or_create_table(catalog)

    arrow_table = _read_detections_from_postgres(round_id=round_id)
    snapshot_id = write_round(table, round_id, arrow_table)

    row_count = arrow_table.num_rows
    print(f"라운드 {round_id} 동기화 완료: {row_count}행 (태그 {round_tag(round_id)}, 스냅샷 {snapshot_id})")
    return row_count


# --- 순수 로직(Postgres 비의존) -------------------------------------------------
# 아래 함수들은 Postgres 없이 pyarrow 테이블만으로 동작하므로, 로컬 sqlite 카탈로그
# + 로컬 웨어하우스로 단위 테스트할 수 있다.


def build_catalog(
    db_path: Path = CATALOG_DB_PATH,
    warehouse_path: Path = WAREHOUSE_PATH,
) -> SqlCatalog:
    """SQLite 카탈로그 + 로컬 파일시스템 웨어하우스를 연다.

    테스트에서는 임시 경로를 주입해 격리된 카탈로그를 만들 수 있다.
    """
    db_path = Path(db_path)
    warehouse_path = Path(warehouse_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    warehouse_path.mkdir(parents=True, exist_ok=True)
    return SqlCatalog(
        CATALOG_NAME,
        uri=f"sqlite:///{db_path}",
        warehouse=f"file://{warehouse_path}",
    )


def get_or_create_table(catalog: SqlCatalog) -> Table:
    """detections 테이블을 로드하거나 생성하고, round_id 파티셔닝을 보장한다."""
    catalog.create_namespace_if_not_exists(NAMESPACE)
    if catalog.table_exists(TABLE_IDENTIFIER):
        table = catalog.load_table(TABLE_IDENTIFIER)
    else:
        table = catalog.create_table(TABLE_IDENTIFIER, schema=ICEBERG_SCHEMA)
    _ensure_partitioned(table)
    return table


def _ensure_partitioned(table: Table) -> None:
    """테이블이 round_id로 파티셔닝돼 있지 않으면 identity 파티션을 추가한다.

    이미 파티션 필드가 있으면 그대로 둔다(멱등). 파티션 진화는 메타데이터
    변경이라 기존에 쌓인 데이터가 있어도 안전하다.
    """
    if table.spec().fields:
        return
    with table.update_spec() as update:
        update.add_field(PARTITION_COLUMN, IdentityTransform(), PARTITION_FIELD_NAME)


def write_full(table: Table, arrow_table: pa.Table) -> int:
    """전체 테이블을 overwrite하고, 존재하는 모든 라운드에 태그를 찍는다.

    반환값은 생성된 스냅샷 ID.
    """
    table.overwrite(arrow_table)  # 전체 교체 — 재실행해도 중복이 생기지 않는다.
    snapshot_id = table.current_snapshot().snapshot_id
    for rid in _distinct_rounds(arrow_table):
        _tag_round(table, rid, snapshot_id)
    return snapshot_id


def write_round(table: Table, round_id: int, arrow_table: pa.Table) -> int:
    """해당 라운드 파티션만 overwrite하고 round-<round_id> 태그를 찍는다.

    overwrite_filter로 round_id == round_id 인 기존 행을 지우고 새로 쓰므로,
    같은 라운드를 다시 써도 중복되지 않는다(멱등). 반환값은 스냅샷 ID.
    """
    table.overwrite(arrow_table, overwrite_filter=EqualTo(PARTITION_COLUMN, round_id))
    snapshot_id = table.current_snapshot().snapshot_id
    _tag_round(table, round_id, snapshot_id)
    return snapshot_id


def _tag_round(table: Table, round_id: int, snapshot_id: int) -> None:
    """round-<round_id> 태그를 주어진 스냅샷에 생성하거나 옮긴다.

    같은 이름의 태그가 이미 있으면 새 스냅샷으로 옮긴다(갱신).
    """
    tag = round_tag(round_id)
    manage = table.manage_snapshots()
    if tag in table.refs():
        manage = manage.remove_tag(tag)
    manage.create_tag(snapshot_id, tag).commit()


def expire_round_snapshots(
    table: Table,
    keep_recent: int = DEFAULT_KEEP_RECENT,
    dry_run: bool = True,
) -> list[int]:
    """오래된 스냅샷 메타데이터를 정리한다(라운드 태그는 항상 보존).

    태그/브랜치가 달린 스냅샷은 Iceberg가 자동으로 보호하므로 round-* 태그가
    가리키는 라운드 스냅샷은 절대 삭제되지 않는다. 그 외 태그 없는 스냅샷 중
    최신 keep_recent개를 남기고 나머지를 만료 대상으로 고른다.

    기본적으로 파괴적이지 않다(dry_run=True): 만료 대상 스냅샷 ID 목록만
    반환하고 실제로 지우지 않는다. 실제로 지우려면 dry_run=False로 호출한다.

    반환값은 (삭제했거나, dry_run이면 삭제 예정인) 스냅샷 ID 목록.
    """
    protected = {ref.snapshot_id for ref in table.refs().values()}

    # 태그 없는 스냅샷을 최신순으로 정렬해 앞 keep_recent개는 남긴다.
    untagged = [s for s in table.snapshots() if s.snapshot_id not in protected]
    untagged.sort(key=lambda s: s.timestamp_ms, reverse=True)
    expire_ids = [s.snapshot_id for s in untagged[max(keep_recent, 0):]]

    if dry_run or not expire_ids:
        return expire_ids

    operation = table.maintenance.expire_snapshots()
    for snapshot_id in expire_ids:
        operation = operation.by_id(snapshot_id)
    operation.commit()
    return expire_ids


def _distinct_rounds(arrow_table: pa.Table) -> list[int]:
    """arrow 테이블에 존재하는 round_id 값(널 제외)을 정렬해 반환한다."""
    if PARTITION_COLUMN not in arrow_table.column_names:
        return []
    values = arrow_table.column(PARTITION_COLUMN).drop_null().unique().to_pylist()
    return sorted(int(v) for v in values)


# --- Postgres 읽기 --------------------------------------------------------------


def _read_detections_from_postgres(round_id: int | None = None) -> pa.Table:
    engine = build_db_engine()
    with engine.connect() as conn:
        if round_id is None:
            rows = conn.execute(SELECT_DETECTIONS).mappings().all()
        else:
            rows = conn.execute(
                SELECT_DETECTIONS_BY_ROUND, {"round_id": round_id}
            ).mappings().all()

    return rows_to_arrow(rows)


def rows_to_arrow(rows: Iterable[dict]) -> pa.Table:
    """Postgres 행(dict) 목록을 Iceberg 스키마에 맞는 pyarrow 테이블로 변환한다."""
    records = [
        {
            "detection_id": str(row["detection_id"]),
            "run_id": row["run_id"],
            "round_id": row["round_id"],
            "technique": row["technique"],
            "channel": row["channel"],
            "rule_name": row["rule_name"],
            "detected_at": _to_naive_utc(row["detected_at"]),
            "container_id": row["container_id"],
            "binary_path": row["binary_path"],
            "created_at": _to_naive_utc(row["created_at"]),
        }
        for row in rows
    ]
    return pa.Table.from_pylist(records, schema=ICEBERG_SCHEMA)


def _to_naive_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _count_rows(catalog: SqlCatalog) -> int:
    table = catalog.load_table(TABLE_IDENTIFIER)  # 디스크에서 최신 메타데이터를 다시 읽는다.
    return table.scan().to_arrow().num_rows


if __name__ == "__main__":
    migrate()
