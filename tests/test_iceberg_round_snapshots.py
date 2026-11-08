"""라운드 단위 Iceberg 스냅샷 관리 로직을 검증한다.

Postgres 없이 돌아가야 CI에서 쓸 수 있으므로, 로컬 sqlite 카탈로그 +
로컬 파일시스템 웨어하우스(pyiceberg SqlCatalog)에 합성 pyarrow 테이블을
써 가며 파티셔닝/태깅/멱등성/타임트래블/보존 로직만 확인한다.

    python3 -m pytest tests/test_iceberg_round_snapshots.py
"""
from __future__ import annotations

from datetime import datetime

import pyarrow as pa
import pytest

from purplebpf.analysis import iceberg_setup as ice


def _rows(round_id: int, detection_ids: list[str]) -> pa.Table:
    """지정한 라운드에 속하는 합성 detections 행들을 만든다."""
    now = datetime(2026, 1, 1, 12, 0, 0)
    records = [
        {
            "detection_id": did,
            "run_id": 100 + i,
            "round_id": round_id,
            "technique": "T1548.001",
            "channel": "syscall",
            "rule_name": "t1548-001-setuid-bit-set",
            "detected_at": now,
            "container_id": "abc",
            "binary_path": "/usr/bin/foo",
            "created_at": now,
        }
        for i, did in enumerate(detection_ids)
    ]
    return pa.Table.from_pylist(records, schema=ice.ICEBERG_SCHEMA)


@pytest.fixture()
def table(tmp_path):
    """임시 경로에 격리된 카탈로그를 열고 detections 테이블을 준비한다."""
    catalog = ice.build_catalog(
        db_path=tmp_path / "catalog.db",
        warehouse_path=tmp_path / "warehouse",
    )
    return ice.get_or_create_table(catalog)


# --- 파티셔닝 -------------------------------------------------------------------


def test_table_is_partitioned_by_round(table):
    fields = table.spec().fields
    assert len(fields) == 1
    assert fields[0].name == ice.PARTITION_FIELD_NAME
    # 소스 컬럼이 round_id 인지 확인한다.
    source = table.schema().find_column_name(fields[0].source_id)
    assert source == ice.PARTITION_COLUMN


def test_ensure_partitioned_is_idempotent(table):
    # 두 번 호출해도 파티션 필드가 늘어나지 않아야 한다.
    ice._ensure_partitioned(table)
    ice._ensure_partitioned(table)
    assert len(table.spec().fields) == 1


# --- 태깅 & 멱등성 --------------------------------------------------------------


def test_write_round_creates_tag(table):
    ice.write_round(table, 1, _rows(1, ["a", "b"]))
    assert ice.round_tag(1) in table.refs()
    assert table.snapshot_by_name(ice.round_tag(1)) is not None


def test_sync_round_is_idempotent(table):
    ice.write_round(table, 1, _rows(1, ["a", "b"]))
    ice.write_round(table, 1, _rows(1, ["a", "b"]))  # 같은 라운드 재동기화
    rows = table.scan().to_arrow()
    assert rows.num_rows == 2  # 중복 없음


def test_write_round_overwrites_only_its_partition(table):
    ice.write_round(table, 1, _rows(1, ["a", "b"]))
    ice.write_round(table, 2, _rows(2, ["c"]))
    # 라운드 2를 다시 써도 라운드 1 데이터는 그대로 남아야 한다.
    ice.write_round(table, 2, _rows(2, ["c", "d"]))

    rows = table.scan().to_arrow().to_pylist()
    by_round: dict[int, set[str]] = {}
    for r in rows:
        by_round.setdefault(r["round_id"], set()).add(r["detection_id"])
    assert by_round[1] == {"a", "b"}
    assert by_round[2] == {"c", "d"}


def test_retag_moves_tag_to_new_snapshot(table):
    ice.write_round(table, 1, _rows(1, ["a"]))
    first = table.snapshot_by_name(ice.round_tag(1)).snapshot_id
    ice.write_round(table, 1, _rows(1, ["a", "b"]))
    second = table.snapshot_by_name(ice.round_tag(1)).snapshot_id
    assert first != second  # 태그가 새 스냅샷으로 이동했다.


# --- 타임트래블(라운드 복원) ----------------------------------------------------


def test_round_tag_enables_time_travel(table):
    ice.write_round(table, 1, _rows(1, ["a", "b"]))
    tag1_snapshot = table.snapshot_by_name(ice.round_tag(1)).snapshot_id

    # 이후 라운드 2가 추가돼 테이블이 더 커져도,
    ice.write_round(table, 2, _rows(2, ["c", "d", "e"]))

    # round-1 태그 시점으로 타임트래블하면 라운드 1만 보인다.
    travelled = table.scan(snapshot_id=tag1_snapshot).to_arrow()
    assert travelled.num_rows == 2
    assert set(travelled.column("round_id").to_pylist()) == {1}


# --- 전체 이관(migrate) ---------------------------------------------------------


def test_write_full_tags_all_rounds(table):
    arrow = pa.concat_tables([_rows(1, ["a"]), _rows(2, ["b", "c"]), _rows(3, ["d"])])
    ice.write_full(table, arrow)
    refs = table.refs()
    for rid in (1, 2, 3):
        assert ice.round_tag(rid) in refs
    assert table.scan().to_arrow().num_rows == 4


def test_migrate_full_overwrite_is_idempotent(table):
    arrow = pa.concat_tables([_rows(1, ["a"]), _rows(2, ["b"])])
    ice.write_full(table, arrow)
    ice.write_full(table, arrow)
    assert table.scan().to_arrow().num_rows == 2


# --- 보존/만료 ------------------------------------------------------------------


def test_expire_keeps_tagged_round_snapshots(table):
    # 라운드 3개 → 각각 태그가 달린 스냅샷 3개 + 중간 스냅샷들.
    for rid in (1, 2, 3):
        ice.write_round(table, rid, _rows(rid, [f"d{rid}"]))
    # 태그 없는 스냅샷을 몇 개 더 만든다.
    for i in range(4):
        ice.write_round(table, 9, _rows(9, [f"x{i}"]))

    tagged_before = {
        table.snapshot_by_name(ice.round_tag(rid)).snapshot_id for rid in (1, 2, 3)
    }

    expired = ice.expire_round_snapshots(table, keep_recent=1, dry_run=False)
    assert expired, "만료 대상이 있어야 한다"

    table.refresh()
    # 태그가 달린 라운드 스냅샷은 하나도 지워지지 않았다.
    tagged_after = {
        table.snapshot_by_name(ice.round_tag(rid)).snapshot_id for rid in (1, 2, 3)
    }
    assert tagged_after == tagged_before
    # 만료 대상은 태그 스냅샷과 겹치지 않는다.
    assert tagged_before.isdisjoint(set(expired))


def test_expire_dry_run_is_not_destructive(table):
    for rid in (1, 2, 3):
        ice.write_round(table, rid, _rows(rid, [f"d{rid}"]))
    before = len(table.snapshots())
    candidates = ice.expire_round_snapshots(table, keep_recent=0, dry_run=True)
    table.refresh()
    after = len(table.snapshots())
    assert after == before  # dry_run은 아무것도 지우지 않는다.
    # dry_run이어도 후보 목록은 태그 스냅샷을 제외한다.
    protected = {ref.snapshot_id for ref in table.refs().values()}
    assert protected.isdisjoint(set(candidates))


# --- 플러그인 태그 해석 ---------------------------------------------------------


class _FakeSourceConfig:
    """dbt-duckdb SourceConfig의 .get(meta) 인터페이스만 흉내 낸다."""

    def __init__(self, meta: dict):
        self._meta = meta

    def get(self, key, default=None):
        return self._meta.get(key, default)


def test_plugin_resolve_round_tag():
    plugin = pytest.importorskip("purplebpf.analysis.dbt_plugins.iceberg_plugin")
    resolve = plugin._resolve_round_tag
    assert resolve(_FakeSourceConfig({})) is None  # 기본 동작: 최신
    assert resolve(_FakeSourceConfig({"round_tag": "round-7"})) == "round-7"
    assert resolve(_FakeSourceConfig({"snapshot_tag": "round-9"})) == "round-9"
    assert resolve(_FakeSourceConfig({"round_id": 3})) == ice.round_tag(3)


def test_plugin_load_time_travels_by_tag(tmp_path, monkeypatch):
    plugin_mod = pytest.importorskip("purplebpf.analysis.dbt_plugins.iceberg_plugin")

    catalog = ice.build_catalog(
        db_path=tmp_path / "catalog.db",
        warehouse_path=tmp_path / "warehouse",
    )
    tbl = ice.get_or_create_table(catalog)
    ice.write_round(tbl, 1, _rows(1, ["a", "b"]))
    ice.write_round(tbl, 2, _rows(2, ["c"]))

    plugin = plugin_mod.Plugin.__new__(plugin_mod.Plugin)
    plugin._catalog = catalog

    # 기본(태그 없음): 전체 최신 = 3행
    latest = plugin.load(_FakeSourceConfig({}))
    assert latest.num_rows == 3

    # round-1 태그: 라운드 1 시점 = 2행
    travelled = plugin.load(_FakeSourceConfig({"round_tag": ice.round_tag(1)}))
    assert travelled.num_rows == 2
    assert set(travelled.column("round_id").to_pylist()) == {1}
