"""gemma 공격체인 실행 결과를 HTML 대시보드로 렌더링해 브라우저로 연다.

체인 JSON은 execution_log 테이블이나 별도 파일에 남지 않는다 — execution_log는
실행이 허용된(REVIEW/REJECT로 막히지 않은) 라운드만 기록하고, executor는 생성된
체인을 파일로 저장하지 않는다(Slack으로만 전송됨). 대신 executor가 매 라운드 끝에
stdout으로 찍는 최종 결과 JSON에는 결정(PASS/REVIEW/REJECT/FAIL)과 무관하게 항상
validator level1의 step 목록(order/command)이 들어있고, 이 stdout은 Dagster가
`run_attack_round` 실행 시 compute log로 이미 로컬에 저장해둔다. 이 asset은 그
compute log를 DagsterInstance API로 읽어 최근 라운드들의 체인 정보를 복원한다.

run_attack_round/executor는 이 asset이 절대 건드리지 않는다 — 읽기 전용으로 기존
compute log를 조회할 뿐이다.

로컬 실행 전제: webbrowser.open()은 이 asset을 실행하는 머신에서 브라우저를 띄운다.
서버에 배포해 원격으로 materialize하면 브라우저가 열리지 않는다(그 머신엔 아무 창도
없다) — 로컬 `dagster dev`로 돌릴 때만 의미가 있다.
"""
import json
import re
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from dagster import AssetExecutionContext, AssetKey, MaterializeResult, MetadataValue, asset

from . import constants as C

TEMPLATE_PATH = C.REPO_ROOT / "orchestration" / "templates" / "attack_chain_dashboard.html"
DASHBOARD_OUTPUT_DIR = C.REPO_ROOT / ".dagster_home" / "dashboards"
CHAIN_MARKER = "/*__CHAINS__*/[]"
MAX_ROUNDS = 20

STDOUT_BLOCK_RE = re.compile(
    r"\[run_attack_round\] stdout:\n(\{.*?\n\})\n+\d{4}-\d{2}-\d{2} ", re.S
)
ROUND_ID_RE = re.compile(r"\[run_attack_round\] round_id=(\d+)")
RETURNCODE_RE = re.compile(r"\[run_attack_round\] returncode=(-?\d+)")


def _extract_stdout_json(log_text: str) -> dict | None:
    match = STDOUT_BLOCK_RE.search(log_text)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def _fetch_run_attack_round_log(instance, run_id: str) -> str | None:
    file_key = None
    for record in instance.all_logs(run_id):
        event = record.dagster_event
        if event is None or event.event_type_value != "LOGS_CAPTURED":
            continue
        data = event.event_specific_data
        if data is not None and "run_attack_round" in (data.step_keys or []):
            file_key = data.file_key
            break
    if file_key is None:
        return None

    log_data = instance.compute_log_manager.get_log_data([run_id, "compute_logs", file_key])
    if not log_data.stderr:
        return None
    return log_data.stderr.decode("utf-8", errors="replace")


def _build_round_entry(run_id: str, timestamp: float, log_text: str) -> dict | None:
    result = _extract_stdout_json(log_text)
    if result is None:
        return None

    round_id_match = ROUND_ID_RE.search(log_text)
    returncode_match = RETURNCODE_RE.search(log_text)

    validation = result.get("validation") or {}
    scenario = validation.get("scenario") or {}
    level1 = validation.get("level1") or {}
    steps = level1.get("steps") or []

    technique_id = (
        scenario.get("technique_id")
        or result.get("technique")
        or None
    )
    decision = result.get("decision") or result.get("validation_status")

    return {
        "round_id": int(round_id_match.group(1)) if round_id_match else result.get("round_id"),
        "dagster_run_id": run_id,
        "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        "technique_id": technique_id,
        "decision": decision,
        "returncode": int(returncode_match.group(1)) if returncode_match else None,
        "success": result.get("success"),
        "steps": steps,
        "step_results": result.get("step_results") or [],
        "raw": result,
    }


def _collect_recent_rounds(context: AssetExecutionContext, limit: int) -> list[dict]:
    instance = context.instance
    materializations = instance.fetch_materializations(
        AssetKey("run_attack_round"), limit=limit
    )

    rounds: list[dict] = []
    for record in materializations.records:
        entry = record.event_log_entry
        log_text = _fetch_run_attack_round_log(instance, entry.run_id)
        if log_text is None:
            context.log.warning(f"run_id={entry.run_id}의 compute log를 찾지 못했다. 건너뜀.")
            continue
        round_entry = _build_round_entry(entry.run_id, entry.timestamp, log_text)
        if round_entry is None:
            context.log.warning(f"run_id={entry.run_id} stdout에서 결과 JSON을 파싱하지 못했다. 건너뜀.")
            continue
        rounds.append(round_entry)

    return rounds


def _render_dashboard_html(rounds: list[dict]) -> str:
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    if CHAIN_MARKER not in template:
        raise ValueError(
            f"템플릿에서 주입 지점을 찾지 못했다: {CHAIN_MARKER!r} (템플릿: {TEMPLATE_PATH})"
        )
    chains_json = json.dumps(rounds, ensure_ascii=False, default=str)
    # 체인 command 문자열에 "</script>"가 그대로 들어 있으면 인라인 스크립트가
    # 조기 종료되므로, HTML 파서가 태그 닫힘으로 해석할 수 없게 이스케이프한다.
    chains_json = chains_json.replace("</", "<\\/")
    injected = f"/*__CHAINS__*/{chains_json}"
    return template.replace(CHAIN_MARKER, injected, 1)


@asset
def render_attack_dashboard(context: AssetExecutionContext) -> MaterializeResult:
    """최근 gemma 공격체인 라운드들을 HTML 대시보드로 렌더링하고 브라우저로 연다.

    run_attack_round와는 독립적으로 materialize할 수 있다 — 이미 쌓인 라운드들을
    다시 보고 싶을 때 이 asset만 눌러도 된다. Dagster의 compute log를 읽기만 하므로
    run_attack_round를 다시 실행하지 않는다.
    """
    rounds = _collect_recent_rounds(context, limit=MAX_ROUNDS)
    context.log.info(f"[render_attack_dashboard] {len(rounds)}개 라운드 로드됨")

    html = _render_dashboard_html(rounds)

    DASHBOARD_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = DASHBOARD_OUTPUT_DIR / f"attack_chain_dashboard_{ts}.html"
    output_path.write_text(html, encoding="utf-8")

    opened = webbrowser.open(f"file://{output_path.resolve()}")
    if not opened:
        context.log.warning(
            "브라우저를 여는 데 실패했다 (헤드리스/원격 환경일 수 있음). "
            f"파일을 직접 열어서 확인: {output_path.resolve()}"
        )

    return MaterializeResult(
        metadata={
            "dashboard_path": MetadataValue.path(str(output_path.resolve())),
            "rounds_loaded": len(rounds),
            "browser_opened": opened,
        }
    )
