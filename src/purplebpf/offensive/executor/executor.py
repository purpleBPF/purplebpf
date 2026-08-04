"""공격 체인을 격리된 일회용 Docker 컨테이너에서 실행하고 execution_log에 기록한다.

이 모듈은 탐지 커버리지 측정을 위한 격리 실험 환경이며, 안전이 최우선이다.
- 각 체인은 새로 만든 일회용 컨테이너 안에서만 실행되고, 끝나면 즉시 삭제된다.
- --privileged, --pid=host, --network=host, 호스트 루트 마운트, --cap-add=ALL은
  절대 사용하지 않는다. (아래 컨테이너 생성 옵션 참고)
- 호스트에서 subprocess로 command를 직접 실행하는 일은 없다 — 반드시 컨테이너 내부에서만.
- Tetragon 탐지/detections 기록/조인, Redis 큐, gVisor/Firecracker 강격리는 이 모듈의 스코프가 아니다.
"""
from __future__ import annotations

import argparse
import json
import shlex
import uuid
from datetime import datetime, timezone

import docker
from sqlalchemy import text

from purplebpf.common.config import build_db_engine

BASE_IMAGE = "ubuntu:22.04"
STEP_TIMEOUT_SECONDS = 30
CHANNEL = "syscall"  # 이번 프로토타입은 syscall 채널 고정. io_uring 경로는 다음 단계.
MAX_OUTPUT_LENGTH = 2000  # step_results 출력이 무한정 커지지 않도록 자른다.

INSERT_EXECUTION_LOG = text(
    """
    INSERT INTO execution_log
        (round_id, chain_id, technique, channel, success, started_at, finished_at, container_id)
    VALUES
        (:round_id, :chain_id, :technique, :channel, :success, :started_at, :finished_at, :container_id)
    RETURNING run_id, round_id, chain_id, technique, channel, success, started_at, finished_at,
              container_id, created_at
    """
)


def execute_chain(chain: dict, round_id: int = 1) -> dict:
    technique_id = chain["technique_id"]
    steps = sorted(chain.get("steps") or [], key=lambda step: step["order"])
    if not steps:
        raise ValueError("체인에 steps가 없다.")

    chain_id = uuid.uuid4()
    docker_client = docker.from_env()

    container = docker_client.containers.run(
        BASE_IMAGE,
        command=["sleep", "infinity"],
        detach=True,
        # --- 안전 옵션: 완화하지 않는다 ---
        privileged=False,  # --privileged 금지
        network_mode="bridge",  # --network=host 금지, 기본 브리지 네트워크만 사용
        pid_mode=None,  # --pid=host 금지 (기본값 = 컨테이너 자신의 PID 네임스페이스)
        cap_add=[],  # --cap-add=ALL 금지, 추가 capability 없음
        security_opt=["no-new-privileges"],  # setuid 등을 통한 컨테이너 내 권한 상승 방지
        # volumes를 아예 지정하지 않는다 = 호스트 볼륨 마운트 없음 (호스트 루트 마운트 금지)
    )

    step_results: list[dict] = []
    success = True
    started_at = datetime.now(timezone.utc)
    try:
        for step in steps:
            exit_code, output = _run_step(container, step["command"])
            step_results.append(
                {
                    "order": step["order"],
                    "command": step["command"],
                    "exit_code": exit_code,
                    "output": output[:MAX_OUTPUT_LENGTH],
                }
            )
            if exit_code != 0:
                success = False
                break
    finally:
        finished_at = datetime.now(timezone.utc)
        container_id = container.short_id
        try:
            container.remove(force=True)
        except docker.errors.NotFound:
            pass

    record = _insert_execution_log(
        round_id=round_id,
        chain_id=chain_id,
        technique=technique_id,
        channel=CHANNEL,
        success=success,
        started_at=started_at,
        finished_at=finished_at,
        container_id=container_id,
    )
    record["step_results"] = step_results
    return record


def _run_step(container, command: str) -> tuple[int, str]:
    # 컨테이너 안에서 coreutils timeout으로 각 command를 30초 제한 실행한다.
    wrapped_command = f"timeout {STEP_TIMEOUT_SECONDS}s bash -c {shlex.quote(command)}"
    exec_result = container.exec_run(["bash", "-c", wrapped_command], demux=False)
    output = exec_result.output.decode("utf-8", errors="replace") if exec_result.output else ""
    return exec_result.exit_code, output


def _insert_execution_log(
    *,
    round_id: int,
    chain_id: uuid.UUID,
    technique: str,
    channel: str,
    success: bool,
    started_at: datetime,
    finished_at: datetime,
    container_id: str,
) -> dict:
    engine = build_db_engine()
    with engine.begin() as conn:
        row = conn.execute(
            INSERT_EXECUTION_LOG,
            {
                "round_id": round_id,
                "chain_id": chain_id,
                "technique": technique,
                "channel": channel,
                "success": success,
                "started_at": started_at,
                "finished_at": finished_at,
                "container_id": container_id,
            },
        ).mappings().one()
    return dict(row)


# 실행 후 아래 SELECT로 execution_log에 행이 들어갔는지 확인할 수 있다:
#
#   SELECT run_id, round_id, chain_id, technique, channel, success,
#          started_at, finished_at, container_id, created_at
#   FROM execution_log
#   ORDER BY run_id DESC
#   LIMIT 5;


def main() -> None:
    parser = argparse.ArgumentParser(
        description="공격 체인을 격리된 컨테이너에서 실행하고 execution_log에 기록한다"
    )
    parser.add_argument(
        "technique_id",
        nargs="?",
        default="T1611",
        help="실행할 대상 Technique ID (기본: T1611)",
    )
    parser.add_argument("--round-id", type=int, default=1, help="round_id (기본: 1)")
    args = parser.parse_args()

    from purplebpf.offensive.filter.first_filter import filter_chain
    from purplebpf.offensive.generation.generator import generate_chain

    chain = generate_chain(args.technique_id)
    verdict = filter_chain(chain)
    print("=== 1차 필터 판정 ===")
    print(json.dumps(verdict, indent=2, ensure_ascii=False))

    if verdict["verdict"] == "REJECT":
        print("1차 필터에서 REJECT된 체인이라 실행을 건너뛴다.")
        return

    result = execute_chain(chain, round_id=args.round_id)
    print("=== 실행 결과 (execution_log 기록) ===")
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
