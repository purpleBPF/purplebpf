"""Postgres의 detections 테이블을 로컬 Iceberg 테이블로 이관한다.

로컬 프로토타입용으로 서버 없는 구성을 쓴다: SQLite 카탈로그 + 로컬 파일시스템
웨어하우스(Parquet). execution_log는 Postgres에 그대로 남기고 이관하지 않는다.

멱등성: 실행할 때마다 Iceberg detections 테이블을 Postgres의 현재 상태로
overwrite(전체 교체)한다. 여러 번 실행해도 중복이 생기지 않는다.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
from pyiceberg.catalog.sql import SqlCatalog
from sqlalchemy import text

from purplebpf.common.config import build_db_engine

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG_DB_PATH = REPO_ROOT / "data" / "iceberg" / "catalog.db"
WAREHOUSE_PATH = REPO_ROOT / "data" / "iceberg" / "warehouse"

CATALOG_NAME = "purplebpf"
NAMESPACE = "purplebpf"
TABLE_NAME = "detections"
TABLE_IDENTIFIER = f"{NAMESPACE}.{TABLE_NAME}"

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


def migrate() -> int:
    catalog = _build_catalog()
    table = _get_or_create_table(catalog)

    arrow_table = _read_detections_from_postgres()
    table.overwrite(arrow_table)  # 전체 교체 — 재실행해도 중복이 생기지 않는다.

    row_count = arrow_table.num_rows
    print(f"이관 완료: {row_count}행")

    verified_count = _count_rows(catalog)
    print(f"검증: Iceberg detections 테이블 스캔 결과 {verified_count}행")

    return row_count


def _build_catalog() -> SqlCatalog:
    CATALOG_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    WAREHOUSE_PATH.mkdir(parents=True, exist_ok=True)
    return SqlCatalog(
        CATALOG_NAME,
        uri=f"sqlite:///{CATALOG_DB_PATH}",
        warehouse=f"file://{WAREHOUSE_PATH}",
    )


def _get_or_create_table(catalog: SqlCatalog):
    catalog.create_namespace_if_not_exists(NAMESPACE)
    if catalog.table_exists(TABLE_IDENTIFIER):
        return catalog.load_table(TABLE_IDENTIFIER)
    return catalog.create_table(TABLE_IDENTIFIER, schema=ICEBERG_SCHEMA)


def _read_detections_from_postgres() -> pa.Table:
    engine = build_db_engine()
    with engine.connect() as conn:
        rows = conn.execute(SELECT_DETECTIONS).mappings().all()

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
