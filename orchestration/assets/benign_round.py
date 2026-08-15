"""정상 워크로드를 돌려 오탐을 재는 asset.

공격만 돌리면 재현율밖에 안 나온다. 규칙을 넓히면 재현율은 올라가는데
정상 동작에도 뜨기 시작한다. 그 대가를 같이 재지 않으면 루프가 규칙을
계속 넓히는 쪽으로만 간다. 그래서 공격 라운드마다 정상 라운드를 붙인다.

`overall_metrics` 뷰가 round_id 로 두 쪽을 조인하므로 라운드 번호를 공유한다.

수집 방식은 두 가지다.
  self_collect  이 asset 이 Mapper 를 직접 띄우고 워크로드가 끝나면 내린다.
                demo/run_benign.sh 와 같은 방식이라 단독으로 돌아간다.
  daemon        VM 에 Mapper 가 상시 떠 있다고 보고 워크로드만 실행한다.
                상시 Mapper 가 있는데 self_collect 를 쓰면 같은 이벤트를
                둘이 기록해 detections 가 중복된다.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from dagster import AssetExecutionContext, Failure, MaterializeResult, MetadataValue, asset

from . import constants as C
from .coverage_loop import collect_detections
from .rounds import _env_with_dotenv

# 상시 Mapper 를 쓰는 환경이면 PBPF_BENIGN_SELF_COLLECT=0 으로 끈다.
SELF_COLLECT = os.environ.get("PBPF_BENIGN_SELF_COLLECT", "1") != "0"

# Mapper 가 gRPC 스트림에 붙기까지 걸리는 시간. 이 사이에 실행된 워크로드는
# 이벤트가 안 잡혀 오탐을 놓친다. 실측으로 6초면 충분했다.
MAPPER_WARMUP_SECONDS = int(os.environ.get("PBPF_MAPPER_WARMUP_SECONDS", "6"))


def _scenario_count() -> int:
    return len(list(Path(C.BENIGN_SCENARIO_DIR).glob("*.json")))


def _collection_window(count: int) -> int:
    """수집 창 길이. 시나리오 하나에 컨테이너를 띄우고 지우는 왕복이 실측 2초쯤이다.

    창이 짧으면 뒤쪽 워크로드의 이벤트가 창 밖에서 도착해 오탐을 놓친다.
    놓친 오탐은 정밀도를 실제보다 높게 보이게 하므로 넉넉하게 잡는다.
    """
    if os.environ.get("PBPF_BENIGN_WINDOW_SECONDS"):
        return C.BENIGN_WINDOW_SECONDS
    return count * 3 + 25 + MAPPER_WARMUP_SECONDS


def _docker_host() -> str:
    return f"unix://{Path.home()}/.lima/{C.LIMA_VM_NAME}/sock/docker.sock"


def _start_mapper(context: AssetExecutionContext, window: int) -> subprocess.Popen:
    """VM 의 이벤트 스트림을 맥의 Mapper 로 넘긴다.

    stdin 을 /dev/null 로 막는 것은 limactl 쪽에 걸어야 한다. 파이프 끝에 걸면
    Mapper 가 이벤트 대신 /dev/null 을 읽어 아무것도 기록하지 않는다.
    """
    stream = subprocess.Popen(
        ["limactl", "shell", C.LIMA_VM_NAME, "--",
         "docker", "exec", "tetragon", "timeout", str(window), "tetra", "getevents", "-o", "json"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    mapper = subprocess.Popen(
        [str(C.VENV_PYTHON), "-m", "purplebpf.defensive.mapper.mapper"],
        stdin=stream.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, cwd=str(C.REPO_ROOT), env={**_env_with_dotenv(), "PYTHONPATH": "src"},
    )
    stream.stdout.close()  # 스트림이 끝나면 Mapper 가 EOF 를 보게 한다
    context.log.info(f"Mapper 기동. {window}초 수집, {MAPPER_WARMUP_SECONDS}초 대기 후 워크로드 시작")
    time.sleep(MAPPER_WARMUP_SECONDS)
    return mapper


@asset(deps=[collect_detections])
def run_benign_round(context: AssetExecutionContext, round_id: int) -> MaterializeResult:
    """정상 워크로드를 컨테이너에서 실행하고 benign_log 에 기록한다.

    collect_detections 뒤에 두는 것은 Mapper 가 겹치지 않게 하려는 것이다.
    공격 수집과 정상 수집이 동시에 돌면 같은 이벤트를 둘이 적는다.
    """
    count = _scenario_count()
    if count == 0:
        raise Failure(description=f"시나리오가 없다: {C.BENIGN_SCENARIO_DIR}")

    mapper = _start_mapper(context, _collection_window(count)) if SELF_COLLECT else None

    cmd = [str(C.VENV_PYTHON), "-m", "purplebpf.offensive.executor.benign_runner",
           "--dir", str(C.BENIGN_SCENARIO_DIR), "--round-id", str(round_id)]
    context.log.info(f"[run_benign_round] 실행: {' '.join(cmd)}")
    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=str(C.REPO_ROOT),
        env={**_env_with_dotenv(), "PYTHONPATH": "src", "DOCKER_HOST": _docker_host()},
    )
    context.log.info(f"[run_benign_round] returncode={result.returncode}")
    if result.stdout.strip():
        context.log.info(f"[run_benign_round] stdout:\n{result.stdout}")

    recorded = None
    if mapper is not None:
        context.log.info("Mapper 종료 대기")
        mapper_out, _ = mapper.communicate()
        recorded = sum(1 for line in mapper_out.splitlines() if line.startswith("기록"))
        context.log.info(f"detections 기록 {recorded} 건")

    if result.returncode != 0:
        raise Failure(
            description=f"정상 워크로드 실행 실패 (returncode={result.returncode})",
            metadata={
                "command": MetadataValue.md(f"`{' '.join(cmd)}`"),
                "stderr_tail": result.stderr[-2000:],
            },
        )

    metadata = {
        "round_id": round_id,
        "시나리오수": count,
        "수집방식": "self_collect" if SELF_COLLECT else "daemon",
        "stdout_tail": result.stdout[-2000:],
    }
    if recorded is not None:
        metadata["detections_기록"] = recorded
    return MaterializeResult(metadata=metadata)
