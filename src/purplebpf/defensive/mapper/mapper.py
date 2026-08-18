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

# 매핑의 단일 출처는 레포 루트의 rules/rule_mapping.yaml 이다.
# 룰과 매핑은 같은 사람이 관리하므로 룰 옆에 두고, Mapper 는 읽기만 한다.
# VM 안에서 레포 경로가 다르면 PBPF_RULE_MAPPING 으로 덮어쓴다.
RULE_MAPPING_PATH = Path(
    os.environ.get("PBPF_RULE_MAPPING")
    or Path(__file__).resolve().parents[4] / "rules" / "rule_mapping.yaml"
)
CHANNEL = "syscall"  # 이번 프로토타입은 syscall 채널 고정.

# Tetragon JSON 이벤트에서 policy_name/process 정보가 담기는 최상위 이벤트 타입들.
# process_exec은 TracingPolicy 없이 기본 센서가 항상 내보내는 exec 스트림이다.
# policy_name이 안 붙으므로 stream_rules 판정에서만 쓰인다.
EVENT_BODY_KEYS = (
    "process_kprobe",
    "process_tracepoint",
    "process_lsm",
    "process_uprobe",
    "process_exec",
)

FRACTIONAL_SECONDS_RE = re.compile(r"(\.\d{6})\d*")

INSERT_SQL = """
    INSERT INTO detections
        (run_id, round_id, technique, channel, rule_name, detected_at, container_id, binary_path)
    VALUES
        (NULL, NULL, %s, %s, %s, %s, %s, %s)
"""


def main() -> None:
    policy_mapping, stream_rules = _load_rule_mapping()

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

            _handle_event(event, policy_mapping, stream_rules, conn)
    except KeyboardInterrupt:
        print("\nCtrl+C로 종료한다.")
    finally:
        conn.close()


def _handle_event(event: dict, policy_mapping: dict, stream_rules: dict, conn) -> None:
    body = _extract_event_body(event)
    if body is None:
        return

    # 1차: policy_name 기반(TracingPolicy) 매칭. 이벤트에 policy_name이 있는데
    # rule_mapping.yaml의 policies에 없으면 실패로 본다(technique=None).
    policy_name = body.get("policy_name") or event.get("policy_name")
    rule_name = policy_name
    technique = policy_mapping.get(policy_name) if policy_name else None

    # 2차: policies 매칭이 실패했거나(policy_name이 있는데 매핑에 없음) 애초에
    # policy_name이 없는 경우(예: TracingPolicy 없이 나오는 기본 process_exec
    # 스트림) — stream_rules로 판정해본다. policies에서 먼저 매치됐으면 여긴
    # 안 타므로 이중 기록은 안 된다.
    if technique is None:
        rule_name, technique = _match_stream_rules(body, stream_rules)

    if technique is None:
        if policy_name:
            print(f"경고: rule_mapping.yaml에 없는 policy_name, 건너뜀: {policy_name}", file=sys.stderr)
        return

    process = body.get("process") or {}
    binary_path = _truncate(process.get("binary"), 256)
    container_id = _truncate(
        process.get("docker") or (process.get("container") or {}).get("id"), 64
    )

    # 컨테이너 밖에서 난 이벤트는 버린다.
    #
    # 공격은 컨테이너 안에서만 실행하는데 규칙에는 컨테이너 한정 조건이 없어서
    # 호스트 활동까지 전부 올라온다. 가장 큰 것이 runc 다. 컨테이너를 만들려면
    # 네임스페이스를 새로 만들어야 하므로 setns 와 unshare 를 부르고, 그것이
    # T1611 규칙에 그대로 걸린다. 공격이 아니라 도커가 제 일을 한 것이다.
    #
    # 커널 안에서 거르는 편이 이벤트 양까지 줄여 낫지만, Tetragon 의
    # matchNamespaces 는 부팅마다 바뀌는 네임스페이스 inode 번호를 값으로
    # 요구해서 정책 파일에 적어둘 수가 없다. 그래서 여기서 거른다.
    # 이벤트 양은 안 줄고 기록만 줄어든다.
    #
    # PBPF_KEEP_HOST_EVENTS=1 을 주면 거르지 않는다. 호스트 대상 기법을
    # 측정할 때나 오탐 내역을 살펴볼 때 쓴다.
    if not container_id and not os.environ.get("PBPF_KEEP_HOST_EVENTS"):
        return

    detected_at = _parse_timestamp(event.get("time") or body.get("time")) or datetime.now(timezone.utc)

    with conn.cursor() as cur:
        cur.execute(
            INSERT_SQL,
            (technique, CHANNEL, rule_name, detected_at, container_id, binary_path),
        )

    print(f"기록: technique={technique} rule={rule_name} binary={binary_path}")


def _match_stream_rules(body: dict, stream_rules: dict) -> tuple[str | None, str | None]:
    """stream_rules 중 anomalous-shell-spawn만 판정한다 (rule_name, technique)로 반환.

    process.binary가 shell_binaries에 전체경로로 완전일치하고, parent.binary가
    parent_contains 중 하나를 부분문자열로 포함하면 T1059.004로 본다. 매치 없으면
    (None, None).

    setuid-exec-escalation(process_credentials.uid != euid 비교)은 조건 성격이
    문자열 매치와 달라 범용 조건 해석기 대신 이 전용 함수로만 처리한다 — 이번
    범위 밖이라 여기서는 다루지 않는다.
    """
    rule = stream_rules.get("anomalous-shell-spawn")
    if not rule:
        return None, None

    shell_binaries = rule.get("shell_binaries") or []
    parent_contains = rule.get("parent_contains") or []

    process_binary = (body.get("process") or {}).get("binary") or ""
    parent_binary = (body.get("parent") or {}).get("binary") or ""

    if process_binary not in shell_binaries:
        return None, None
    if not any(server in parent_binary for server in parent_contains):
        return None, None

    return "anomalous-shell-spawn", rule.get("technique")


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


def _load_rule_mapping() -> tuple[dict[str, str], dict[str, dict]]:
    """rules/rule_mapping.yaml 을 읽어 policies 와 stream_rules 를 각각 다른 구조로 편다.

    policies: {policy_name: technique}. TracingPolicy 이벤트는 policy_name 으로
    식별되므로 이 평평한 대응표로 충분하다.

    stream_rules: {rule_name: {technique, shell_binaries, parent_contains, ...}}.
    TracingPolicy 없이 기본 exec 스트림에서 유저스페이스로 판정하는 탐지라
    policy_name 으로 안 걸린다. 항목 구조가 규칙마다 달라(문자열 매치 vs
    uid/euid 비교) 그대로 dict 로 넘기고, 실제 판정은 규칙 이름별 전용 함수
    (_match_stream_rules 등)에서 필요한 필드만 꺼내 쓴다.
    """
    with RULE_MAPPING_PATH.open(encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    policies: dict[str, str] = {}
    for policy_name, spec in (doc.get("policies") or {}).items():
        technique = spec.get("technique") if isinstance(spec, dict) else spec
        if isinstance(technique, list):
            # 탐지 하나가 기법 여럿을 덮는 경우. detections.technique 는 단일 값이라
            # 첫 번째만 쓴다. 정확히 가르려면 Mapper 가 경로·인자로 분기해야 한다.
            print(
                f"경고: {policy_name} 에 technique 이 여럿이다({technique}). 첫 번째만 쓴다.",
                file=sys.stderr,
            )
            technique = technique[0] if technique else None
        if technique:
            policies[policy_name] = technique

    if not policies:
        raise RuntimeError(f"{RULE_MAPPING_PATH} 의 policies 섹션이 비어 있다.")

    stream_rules: dict[str, dict] = dict(doc.get("stream_rules") or {})

    return policies, stream_rules


if __name__ == "__main__":
    main()
