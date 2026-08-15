""""공격 실행 → 탐지 수집 → 측정 갱신"을 순서대로 묶는 수동 트리거 파이프라인.

정해진 스케줄은 없다 — Dagster UI에서 "Materialize all"을 누르거나
`dagster asset materialize`로 사람이 직접 시작시켰을 때만 돈다.
각 asset은 subprocess로 셸 명령 하나를 실행하고 반환 코드로 성공/실패를 정한다.
"""
import subprocess

from dagster import AssetExecutionContext, Failure, MaterializeResult, MetadataValue, asset

from . import constants as C


def _run_shell(context: AssetExecutionContext, label: str, cmd: list[str]) -> subprocess.CompletedProcess:
    context.log.info(f"[{label}] 실행: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    context.log.info(f"[{label}] returncode={result.returncode}")
    if result.stdout.strip():
        context.log.info(f"[{label}] stdout:\n{result.stdout}")
    if result.stderr.strip():
        context.log.info(f"[{label}] stderr:\n{result.stderr}")
    return result


def _require_success(label: str, cmd: list[str], result: subprocess.CompletedProcess) -> None:
    if result.returncode != 0:
        raise Failure(
            description=f"{label} 실패 (returncode={result.returncode})",
            metadata={
                "command": MetadataValue.md(f"`{' '.join(cmd)}`"),
                "returncode": result.returncode,
                "stderr_tail": result.stderr[-2000:],
            },
        )


def _materialize_result(label: str, cmd: list[str], result: subprocess.CompletedProcess) -> MaterializeResult:
    return MaterializeResult(
        metadata={
            "command": MetadataValue.md(f"`{' '.join(cmd)}`"),
            "returncode": result.returncode,
            "stdout_tail": result.stdout[-2000:],
        }
    )


def _limactl_shell(bash_command: str) -> list[str]:
    return ["limactl", "shell", C.LIMA_VM_NAME, "--", "bash", "-c", bash_command]


@asset
def run_attack_round(context: AssetExecutionContext, round_id: int) -> MaterializeResult:
    """Lima VM 안에서 Executor로 공격 체인 한 라운드를 실행한다 (execution_log에 기록됨).

    round_id 를 넘기지 않으면 Executor 기본값 1 로 들어간다. 그러면 파이프라인을
    돌릴 때마다 같은 라운드에 쌓여 채점이 겹친다. 커버리지 뷰가 라운드로
    묶어 세기 때문에 건수만 배로 늘고 세대별 변화가 안 보인다.
    """
    bash_command = (
        f"cd {C.VM_REPO_ROOT} && source {C.VM_ENV_FILE} && "
        f"python3 -m purplebpf.offensive.executor.executor {C.TARGET_TECHNIQUE_ID} "
        f"--round-id {round_id}"
    )
    cmd = _limactl_shell(bash_command)
    result = _run_shell(context, "run_attack_round", cmd)
    _require_success("Executor 실행", cmd, result)
    return _materialize_result("run_attack_round", cmd, result)


@asset(deps=[run_attack_round])
def collect_detections(context: AssetExecutionContext) -> MaterializeResult:
    """Lima VM 안에서 지정 시간만큼 탐지 이벤트를 모아 Mapper로 detections에 적재한다.

    `timeout`으로 걸어둔 tetra getevents는 정상적으로도 SIGTERM(반환 코드 124)으로
    끝나므로, 파이프(`|`)의 최종 반환 코드는 (bash 기본 동작대로) 오른쪽인
    mapper의 반환 코드를 따른다 — 의도적으로 pipefail을 켜지 않는다.
    """
    bash_command = (
        f"cd {C.VM_REPO_ROOT} && source {C.VM_ENV_FILE} && "
        f"timeout {C.DETECTION_WINDOW_SECONDS} docker exec tetragon tetra getevents -o json "
        f"| python3 -m purplebpf.defensive.mapper.mapper"
    )
    cmd = _limactl_shell(bash_command)
    result = _run_shell(context, "collect_detections", cmd)
    _require_success("탐지 수집(Mapper)", cmd, result)
    return _materialize_result("collect_detections", cmd, result)


@asset(deps=[collect_detections])
def sync_iceberg(context: AssetExecutionContext) -> MaterializeResult:
    """맥 호스트에서 Postgres의 detections를 로컬 Iceberg 테이블로 동기화한다."""
    cmd = [str(C.VENV_PYTHON), "-m", "purplebpf.analysis.iceberg_setup"]
    result = _run_shell(context, "sync_iceberg", cmd)
    _require_success("Iceberg 동기화", cmd, result)
    return _materialize_result("sync_iceberg", cmd, result)


@asset(deps=[sync_iceberg])
def run_coverage_dbt(context: AssetExecutionContext) -> MaterializeResult:
    """coverage 마트를 재계산하고 coverage_history에 append한다."""
    cmd = [
        str(C.VENV_DBT), "run",
        "--project-dir", str(C.DBT_PROJECT_DIR),
        "--profiles-dir", str(C.DBT_PROFILES_DIR),
    ]
    result = _run_shell(context, "run_coverage_dbt", cmd)
    _require_success("dbt run", cmd, result)
    return _materialize_result("run_coverage_dbt", cmd, result)


@asset(deps=[run_coverage_dbt])
def test_coverage_dbt(context: AssetExecutionContext) -> MaterializeResult:
    """coverage 데이터 테스트를 돈다. 실패해도 경고만 남기고 파이프라인은 완료 처리한다."""
    cmd = [
        str(C.VENV_DBT), "test",
        "--project-dir", str(C.DBT_PROJECT_DIR),
        "--profiles-dir", str(C.DBT_PROFILES_DIR),
    ]
    result = _run_shell(context, "test_coverage_dbt", cmd)
    passed = result.returncode == 0
    if not passed:
        context.log.warning(
            f"dbt test 실패(returncode={result.returncode}) — 파이프라인은 중단하지 않고 경고만 남긴다."
        )
    return MaterializeResult(
        metadata={
            "command": MetadataValue.md(f"`{' '.join(cmd)}`"),
            "returncode": result.returncode,
            "passed": passed,
            "stdout_tail": result.stdout[-2000:],
        }
    )
