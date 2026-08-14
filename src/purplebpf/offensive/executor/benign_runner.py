"""정상 워크로드를 실행하고 benign_log 에 기록한다.

오탐을 재려면 공격이 아닌 실행 기록이 필요하다. 공격 Executor 와 같은
컨테이너 설정으로 돌려야 비교가 성립하므로 옵션을 그대로 맞췄다.

공격 쪽과 다른 점은 둘이다.
  기록하는 테이블이 benign_log 다. execution_log 의 technique 컬럼에는
  ATT&CK 형식 제약이 걸려 있어 정상 워크로드를 넣을 수 없다.
  실패해도 그대로 기록한다. 공격은 실패하면 측정 불가지만, 정상 워크로드는
  명령이 실패해도 그 사이에 규칙이 떴는지가 여전히 의미 있다.

사용법:
    python -m purplebpf.offensive.executor.benign_runner --dir demo/benign
    python -m purplebpf.offensive.executor.benign_runner --file demo/benign/x.json
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shlex
import uuid
from datetime import datetime, timezone

import docker
from sqlalchemy import text

from purplebpf.common.config import build_db_engine

BASE_IMAGE = "ubuntu:22.04"
STEP_TIMEOUT_SECONDS = 30
MAX_OUTPUT_LENGTH = 2000

INSERT_BENIGN_LOG = text(
    """
    INSERT INTO benign_log
        (round_id, chain_id, label, kind, success, started_at, finished_at,
         container_id, expect_silent)
    VALUES
        (:round_id, :chain_id, :label, :kind, :success, :started_at, :finished_at,
         :container_id, :expect_silent)
    RETURNING run_id, round_id, label, kind, success, container_id
    """
)


def run_scenario(scenario: dict, round_id: int = 1) -> dict:
    label = scenario["label"]
    steps = sorted(scenario.get("steps") or [], key=lambda s: s["order"])
    if not steps:
        raise ValueError(f"{label}: steps 가 없다.")

    chain_id = uuid.uuid4()
    client = docker.from_env()

    # 공격 Executor 와 같은 설정. 완화하지 않는다.
    container = client.containers.run(
        BASE_IMAGE,
        command=["sleep", "infinity"],
        detach=True,
        privileged=False,
        network_mode="bridge",
        pid_mode=None,
        cap_add=[],
        security_opt=["no-new-privileges"],
    )

    results: list[dict] = []
    success = True
    started_at = datetime.now(timezone.utc)
    try:
        for step in steps:
            wrapped = f"timeout {STEP_TIMEOUT_SECONDS}s bash -c {shlex.quote(step['command'])}"
            r = container.exec_run(["bash", "-c", wrapped], demux=False)
            out = r.output.decode("utf-8", errors="replace") if r.output else ""
            results.append({"order": step["order"], "exit_code": r.exit_code,
                            "output": out[:MAX_OUTPUT_LENGTH]})
            # 공격과 달리 실패해도 멈추지 않는다. 뒷 단계도 정상 동작이므로
            # 그것들이 규칙을 건드리는지 계속 봐야 한다.
            if r.exit_code != 0:
                success = False
    finally:
        finished_at = datetime.now(timezone.utc)
        container_id = container.short_id
        try:
            container.remove(force=True)
        except docker.errors.NotFound:
            pass

    engine = build_db_engine()
    with engine.begin() as conn:
        row = conn.execute(INSERT_BENIGN_LOG, {
            "round_id": round_id,
            "chain_id": chain_id,
            "label": label,
            "kind": scenario.get("kind", "normal"),
            "success": success,
            "started_at": started_at,
            "finished_at": finished_at,
            "container_id": container_id,
            "expect_silent": scenario.get("expect_silent") or [],
        }).mappings().one()

    record = dict(row)
    record["step_results"] = results
    return record


def main() -> None:
    ap = argparse.ArgumentParser(description="정상 워크로드를 실행하고 benign_log 에 기록한다")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", help="시나리오 JSON 하나")
    g.add_argument("--dir", help="시나리오 JSON 이 든 디렉터리")
    ap.add_argument("--round-id", type=int, default=1)
    args = ap.parse_args()

    paths = ([pathlib.Path(args.file)] if args.file
             else sorted(pathlib.Path(args.dir).glob("*.json")))
    if not paths:
        raise SystemExit("실행할 시나리오가 없다.")

    for p in paths:
        scenario = json.loads(p.read_text(encoding="utf-8"))
        rec = run_scenario(scenario, round_id=args.round_id)
        print(f'{rec["label"]:28} {rec["kind"]:6} '
              f'success={str(rec["success"]).lower():5} {rec["container_id"]}')


if __name__ == "__main__":
    main()
