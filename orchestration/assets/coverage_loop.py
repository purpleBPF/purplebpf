""""공격 실행 → 측정 갱신"을 순서대로 묶는 수동 트리거 파이프라인.

탐지 수집(Mapper)은 이 파이프라인에 없다 — asset으로 돌리면 "공격 뒤에 수집 시작"
타이밍 때문에 이벤트를 놓쳐(detects=0) Dagster 밖에서 상시 데몬으로 띄워둔다.
Mapper가 항상 켜져 있으므로 공격이 나가면 자동으로 잡힌다.

정해진 스케줄은 없다 — Dagster UI에서 "Materialize all"을 누르거나
`dagster asset materialize`로 사람이 직접 시작시켰을 때만 돈다.
각 asset은 subprocess로 셸 명령 하나를 실행하고 반환 코드로 성공/실패를 정한다.
"""
import subprocess

from dagster import AssetExecutionContext, Failure, MaterializeResult, MetadataValue, asset
from sqlalchemy import text

from purplebpf.common.config import build_db_engine

from . import constants as C

NEXT_ROUND_ID_SQL = text("SELECT COALESCE(MAX(round_id), 0) + 1 FROM execution_log")


def _next_round_id() -> int:
    engine = build_db_engine()
    with engine.connect() as conn:
        return conn.execute(NEXT_ROUND_ID_SQL).scalar_one()


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
def run_attack_round(context: AssetExecutionContext) -> MaterializeResult:
    """Lima VM 안에서 Executor로 공격 체인 한 라운드를 실행한다 (execution_log에 기록됨)."""
    round_id = _next_round_id()
    context.log.info(f"[run_attack_round] round_id={round_id}")
    bash_command = (
        f"cd {C.VM_REPO_ROOT} && source {C.VM_ENV_FILE} && "
        f"python3 -m purplebpf.offensive.executor.executor {C.TARGET_TECHNIQUE_ID} --round-id {round_id}"
    )
    cmd = _limactl_shell(bash_command)
    result = _run_shell(context, "run_attack_round", cmd)
    
    # --- 수정된 부분: 0(성공), 2(REJECT), 3(REVIEW) 모두 정상 흐름으로 처리 ---
    if result.returncode not in (0, 2, 3):
        raise Failure(
            description=f"Executor 실행 실패 (returncode={result.returncode})",
            metadata={
                "command": MetadataValue.md(f"`{' '.join(cmd)}`"),
                "returncode": result.returncode,
                "stderr_tail": result.stderr[-2000:],
            },
        )
    elif result.returncode == 2:
        context.log.warning("체인이 REJECT(반려) 되어 실행이 차단되었습니다. 파이프라인을 계속 진행합니다.")
    elif result.returncode == 3:
        context.log.info("체인이 REVIEW(검토) 상태가 되어 Slack 알림이 발송되었습니다. 파이프라인을 계속 진행합니다.")
    # -------------------------------------------------------------------------
    
    return _materialize_result("run_attack_round", cmd, result)


@asset(deps=[run_attack_round])
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
