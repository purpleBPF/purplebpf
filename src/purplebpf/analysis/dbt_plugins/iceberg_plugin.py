"""dbt-duckdb 플러그인 — Iceberg의 detections 테이블을 pyarrow로 읽어 DuckDB 소스로 등록한다.

dbt-duckdb에 내장된 iceberg 플러그인 대신 이 플러그인을 쓰는 이유: 카탈로그 경로를
iceberg_setup.py의 상수(CATALOG_DB_PATH, WAREHOUSE_PATH 등)로 그대로 재사용해야 한다.
profiles.yml에 경로를 하드코딩하면 dbt 실행 디렉토리에 따라 상대경로가 어긋날 수 있는데,
iceberg_setup.py의 상수는 파일 위치 기준 절대경로라 dbt를 어디서 실행하든 항상 같은
카탈로그·웨어하우스를 가리킨다.
"""
import os
from typing import Any, Dict

# DuckDB가 내부적으로 pyarrow 등록 테이블을 스캔할 때 자체 워커 스레드에서 처음으로
# pyarrow의 mimalloc 할당자를 건드리면 스레드-로컬 힙 초기화가 세그폴트를 낸다
# (이 환경의 pyarrow/Python 3.14 조합에서 재현됨). mimalloc 대신 시스템 할당자를
# 쓰게 하면 이 크래시가 사라지는데, pyarrow가 처음 임포트되는 시점(대개 이 모듈보다
# 먼저, dbt 자체 의존성 로딩 중)보다 먼저 설정돼야 한다. 그래서 실질적인 고정값은
# .env의 ARROW_DEFAULT_MEMORY_POOL=system이고(반드시 dbt 실행 전에 로드돼야 함),
# 여기서는 .env 로딩을 잊었을 때를 위한 방어적 fallback으로만 설정해둔다.
os.environ.setdefault("ARROW_DEFAULT_MEMORY_POOL", "system")

from dbt.adapters.duckdb.plugins import BasePlugin
from pyiceberg.catalog.sql import SqlCatalog

from purplebpf.analysis.iceberg_setup import (
    CATALOG_DB_PATH,
    CATALOG_NAME,
    TABLE_IDENTIFIER,
    WAREHOUSE_PATH,
)


class Plugin(BasePlugin):
    def initialize(self, config: Dict[str, Any]) -> None:
        self._catalog = SqlCatalog(
            CATALOG_NAME,
            uri=f"sqlite:///{CATALOG_DB_PATH}",
            warehouse=f"file://{WAREHOUSE_PATH}",
        )

    def load(self, source_config):
        table = self._catalog.load_table(TABLE_IDENTIFIER)
        return table.scan().to_arrow()
