"""DuckDB로 execution_log(Postgres)와 detections(Iceberg)를 조인해 커버리지를 계산한다.

기존에 Postgres 생 SQL로 하던 조인을 DuckDB 계산 엔진으로 교체하는 단계다.
이번 단계는 계산과 콘솔 출력까지만 하고, 결과를 어디에도 저장하지 않는다
(저장은 다음 dbt 단계).
"""
from __future__ import annotations

from collections import Counter

import duckdb
from pyiceberg.catalog.sql import SqlCatalog
from sqlalchemy import text

from purplebpf.analysis.iceberg_setup import (
    CATALOG_DB_PATH,
    CATALOG_NAME,
    TABLE_IDENTIFIER,
    WAREHOUSE_PATH,
)
from purplebpf.common.config import build_db_engine, build_postgres_libpq_dsn

COVERAGE_QUERY = """
    SELECT
      COALESCE(e.technique, d.technique) AS technique,
      COUNT(DISTINCT e.run_id) AS shots,
      COUNT(DISTINCT d.detection_id) AS detects,
      CASE
        WHEN COUNT(e.run_id) > 0 AND COUNT(d.detection_id) > 0 THEN 'TP'
        WHEN COUNT(e.run_id) > 0 AND COUNT(d.detection_id) = 0 THEN 'FN'
        ELSE 'FP'
      END AS result
    FROM execution_log e
    FULL OUTER JOIN detections d ON e.technique = d.technique
    GROUP BY COALESCE(e.technique, d.technique)
    ORDER BY technique
"""

# 기존 Postgres 생 SQL 조인(두 테이블 다 Postgres). DuckDB 결과와 일치하는지 확인하는 기준선.
POSTGRES_REFERENCE_QUERY = text(
    """
    SELECT
      COALESCE(e.technique, d.technique) AS technique,
      COUNT(DISTINCT e.run_id) AS shots,
      COUNT(DISTINCT d.detection_id) AS detects,
      CASE
        WHEN COUNT(e.run_id) > 0 AND COUNT(d.detection_id) > 0 THEN 'TP'
        WHEN COUNT(e.run_id) > 0 AND COUNT(d.detection_id) = 0 THEN 'FN'
        WHEN COUNT(e.run_id) = 0 AND COUNT(d.detection_id) > 0 THEN 'FP'
      END AS result
    FROM execution_log e
    FULL OUTER JOIN detections d ON e.technique = d.technique
    GROUP BY COALESCE(e.technique, d.technique)
    ORDER BY technique
    """
)


def compute_coverage() -> list[dict]:
    conn = duckdb.connect()
    try:
        _attach_postgres_execution_log(conn)
        conn.register("detections", _load_detections_arrow())

        result = conn.sql(COVERAGE_QUERY)
        result.show()

        columns = [col[0] for col in result.description]
        records = [dict(zip(columns, row)) for row in result.fetchall()]
    finally:
        conn.close()

    _print_summary(records)
    return records


def _attach_postgres_execution_log(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute("INSTALL postgres; LOAD postgres;")
    conn_string = build_postgres_libpq_dsn()
    conn.execute(f"ATTACH '{_escape_duckdb_literal(conn_string)}' AS pg (TYPE postgres)")
    conn.execute("CREATE VIEW execution_log AS SELECT * FROM pg.public.execution_log")


def _escape_duckdb_literal(value: str) -> str:
    return value.replace("'", "''")


def _load_detections_arrow():
    catalog = SqlCatalog(
        CATALOG_NAME,
        uri=f"sqlite:///{CATALOG_DB_PATH}",
        warehouse=f"file://{WAREHOUSE_PATH}",
    )
    table = catalog.load_table(TABLE_IDENTIFIER)
    return table.scan().to_arrow()


def _print_summary(records: list[dict]) -> None:
    counts = Counter(record["result"] for record in records)
    print(f"요약: TP={counts.get('TP', 0)} FN={counts.get('FN', 0)} FP={counts.get('FP', 0)}")


def _fetch_postgres_reference() -> list[dict]:
    engine = build_db_engine()
    with engine.connect() as conn:
        rows = conn.execute(POSTGRES_REFERENCE_QUERY).mappings().all()
    return [dict(row) for row in rows]


def verify_against_postgres(duckdb_records: list[dict]) -> bool:
    duckdb_by_technique = {r["technique"]: r["result"] for r in duckdb_records}
    postgres_by_technique = {r["technique"]: r["result"] for r in _fetch_postgres_reference()}

    all_techniques = sorted(set(duckdb_by_technique) | set(postgres_by_technique))
    print(f"\n{'technique':<15}{'duckdb':<10}{'postgres(원본)':<15}{'일치':<6}")
    all_match = True
    for technique in all_techniques:
        duckdb_result = duckdb_by_technique.get(technique, "-")
        postgres_result = postgres_by_technique.get(technique, "-")
        matches = duckdb_result == postgres_result
        all_match = all_match and matches
        print(f"{technique:<15}{duckdb_result:<10}{postgres_result:<15}{'OK' if matches else 'MISMATCH':<6}")

    print("DuckDB 결과가 Postgres 원본 조인 결과와 일치한다." if all_match else "불일치가 있다.")
    return all_match


if __name__ == "__main__":
    coverage_records = compute_coverage()
    verify_against_postgres(coverage_records)
