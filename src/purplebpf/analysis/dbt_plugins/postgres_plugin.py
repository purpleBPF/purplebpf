"""dbt-duckdb 플러그인 — DuckDB 연결이 열릴 때마다 Postgres를 pg 별칭으로 ATTACH한다.

dbt-duckdb에 내장된 postgres 플러그인 대신 이 플러그인을 쓰는 이유: DATABASE_URL을
os.environ에서 직접 파싱해야 한다 (coverage_duckdb.py에서 검증된 방식과 동일).
SQLAlchemy의 Engine.url을 str()로 찍으면 비밀번호가 '***'로 마스킹돼 ATTACH 인증이
실패하는 함정이 있다.
"""
from typing import Any, Dict

from dbt.adapters.duckdb.plugins import BasePlugin
from duckdb import DuckDBPyConnection

from purplebpf.common.config import build_postgres_libpq_dsn

POSTGRES_EXTENSION = "postgres"
ATTACH_ALIAS = "pg"


class Plugin(BasePlugin):
    def initialize(self, config: Dict[str, Any]) -> None:
        pass

    def configure_connection(self, conn: DuckDBPyConnection) -> None:
        conn.install_extension(POSTGRES_EXTENSION)
        conn.load_extension(POSTGRES_EXTENSION)

        dsn = build_postgres_libpq_dsn()
        conn.execute(
            f"ATTACH IF NOT EXISTS '{_escape_duckdb_literal(dsn)}' AS {ATTACH_ALIAS} (TYPE postgres)"
        )


def _escape_duckdb_literal(value: str) -> str:
    return value.replace("'", "''")
