"""Tetragon 이벤트 스트림을 detections 테이블에 기록하는 Mapper.

이 스크립트는 Linux VM 안에서 실행되어, VM의 Tetragon이 내보내는 JSON 이벤트를
읽고 맥 호스트의 Postgres(DATABASE_URL, 보통 host.lima.internal:5433)에 기록한다.
VM 환경에서 표준적으로 쓰는 psycopg2/yaml만 사용한다 (레포의 다른 패키지 의존 없음).

사용법:
    docker exec tetragon tetra getevents -o json | python3 mapper.py
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import yaml

RULE_MAPPING_PATH = Path(__file__).parent / "rule_mapping.yaml"
CHANNEL = "syscall"  # 이번 프로토타입은 syscall 채널 고정.

# Tetragon JSON 이벤트에서 policy_name/process 정보가 담기는 최상위 이벤트 타입들.
EVENT_BODY_KEYS = ("process_kprobe", "process_tracepoint", "process_lsm", "process_uprobe")

FRACTIONAL_SECONDS_RE = re.compile(r"(\.\d{6})\d*")

INSERT_SQL = """
    INSERT INTO detections
        (run_id, round_id, technique, channel, rule_name, detected_at, container_id, binary_path)
    VALUES
        (NULL, NULL, %s, %s, %s, %s, %s, %s)
"""


def main() -> None:
    rule_mapping = _load_rule_mapping()

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL 환경변수가 설정되어 있지 않다.")

    conn = psycopg2.connect(database_url)
    conn.autocommit = True
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"경고: JSON 파싱 실패, 건너뜀: {line[:200]}", file=sys.stderr)
                continue

            _handle_event(event, rule_mapping, conn)
    except KeyboardInterrupt:
        print("\nCtrl+C로 종료한다.")
    finally:
        conn.close()


def _handle_event(event: dict, rule_mapping: dict, conn) -> None:
    body = _extract_event_body(event)
    if body is None:
        return

    policy_name = body.get("policy_name") or event.get("policy_name")
    if not policy_name:
        return

    technique = rule_mapping.get(policy_name)
    if technique is None:
        print(f"경고: rule_mapping.yaml에 없는 policy_name, 건너뜀: {policy_name}", file=sys.stderr)
        return

    process = body.get("process") or {}
    binary_path = _truncate(process.get("binary"), 256)
    container_id = _truncate(
        process.get("docker") or (process.get("container") or {}).get("id"), 64
    )
    detected_at = _parse_timestamp(event.get("time") or body.get("time")) or datetime.now(timezone.utc)

    with conn.cursor() as cur:
        cur.execute(
            INSERT_SQL,
            (technique, CHANNEL, policy_name, detected_at, container_id, binary_path),
        )

    print(f"기록: technique={technique} binary={binary_path}")


def _extract_event_body(event: dict) -> dict | None:
    for key in EVENT_BODY_KEYS:
        if key in event:
            return event[key]
    return None


def _parse_timestamp(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = FRACTIONAL_SECONDS_RE.sub(r"\1", text)  # 나노초 등 6자리 초과 소수점을 마이크로초로 자른다.
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value[:limit]


def _load_rule_mapping() -> dict:
    with RULE_MAPPING_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


if __name__ == "__main__":
    main()
