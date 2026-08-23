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
import logging
import re
import shlex
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import docker
from sqlalchemy import text

from purplebpf.common.config import build_db_engine

BASE_IMAGE = "ubuntu:22.04"
STEP_TIMEOUT_SECONDS = 30
CHANNEL = "syscall"  # 이번 프로토타입은 syscall 채널 고정. io_uring 경로는 다음 단계.
MAX_OUTPUT_LENGTH = 2000  # step_results 출력이 무한정 커지지 않도록 자른다.

EXIT_SUCCESS = 0
EXIT_EXECUTION_FAILED = 1
EXIT_REJECTED = 2
EXIT_REVIEW = 3
EXIT_SYSTEM_ERROR = 4
EXIT_INVALID_INPUT = 5

STANDARD_EXECUTION_POLICY = "STANDARD"
DEMO_ALLOW_REVIEW_POLICY = "DEMO_ALLOW_REVIEW"
_KNOWN_EXECUTION_STATUSES = {"PASS", "REVIEW", "REJECT", "FAIL", "ERROR"}
BLOCKED_CONTAINER_ID = "blocked"  # 실제 docker short id(16진수)와 절대 겹치지 않는 센티널
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")  # execution_log.technique CHECK 제약과 동일

logger = logging.getLogger(__name__)

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


def _validate_execution_gate(chain: dict) -> dict:
    """Validate a chain and allow execution only after an unambiguous full pass."""
    try:
        from purplebpf.offensive.validator.main import validate_scenario_pipeline

        validation = validate_scenario_pipeline(chain)
    except Exception as exc:
        return {
            "decision": "ERROR",
            "reason": "VALIDATOR_ERROR",
            "error": f"{type(exc).__name__}: {exc}",
        }

    if not isinstance(validation, dict):
        return {
            "decision": "ERROR",
            "reason": "VALIDATION_RESULT_INVALID",
            "validation": validation,
        }

    level1 = validation.get("level1")
    level2 = validation.get("level2")
    level3 = validation.get("level3")
    final = validation.get("final")

    level1_status = level1.get("status") if isinstance(level1, dict) else None
    level2_status = level2.get("status") if isinstance(level2, dict) else None
    level3_status = level3.get("status") if isinstance(level3, dict) else None
    final_status = final.get("status") if isinstance(final, dict) else None
    invalid_result = {
        "decision": "ERROR",
        "reason": "VALIDATION_RESULT_INVALID",
        "validation": validation,
    }

    if final_status not in {"PASS", "REVIEW", "REJECT"}:
        return invalid_result
    if level1_status == "FAIL":
        if level2 is None and level3 is None and final_status == "REJECT":
            return {
                "decision": "FAIL",
                "reason": "VALIDATION_REJECTED",
                "validation": validation,
            }
        return invalid_result
    if level1_status != "PASS":
        return invalid_result
    if level2_status in {"FAIL", "REJECT"}:
        if level3 is None and final_status == "REJECT":
            return {
                "decision": "FAIL",
                "reason": "VALIDATION_REJECTED",
                "validation": validation,
            }
        return invalid_result
    if level2_status not in {"PASS", "REVIEW"}:
        return invalid_result
    if level3_status not in {"PASS", "REVIEW", "FAIL", "REJECT"}:
        return invalid_result

    statuses = (level1_status, level2_status, level3_status, final_status)
    if "FAIL" in statuses or "REJECT" in statuses:
        return {
            "decision": "FAIL",
            "reason": "VALIDATION_REJECTED",
            "validation": validation,
        }
    if "REVIEW" in statuses:
        return {
            "decision": "REVIEW",
            "reason": "VALIDATION_REVIEW",
            "validation": validation,
        }
    if statuses == ("PASS", "PASS", "PASS", "PASS"):
        return {
            "decision": "PASS",
            "reason": "VALIDATION_PASSED",
            "validation": validation,
        }
    return invalid_result


def _log_blocked_attempt(round_id: int, chain: dict, decision: str) -> None:
    """REVIEW/REJECT로 실행이 차단된 시도도 execution_log에 남긴다.

    _next_round_id()가 execution_log.round_id의 MAX+1로 다음 라운드 번호를 계산하는데,
    차단된 시도가 기록되지 않으면 MAX가 안 올라가 다음 시도가 같은 round_id를 받는다
    (실측: REVIEW 라운드와 그다음 REJECT 라운드가 둘 다 round_id=2로 찍힘).
    실제 컨테이너가 없으므로 container_id는 실제 docker short id와 절대 겹치지 않는
    센티널을 쓴다 — coverage.sql의 `d.container_id LIKE e.container_id || '%'` 조인이
    빈 문자열 등으로 오염되면 안 되기 때문이다.
    기록 실패가 REVIEW/REJECT 차단 자체(human-in-the-loop)를 막으면 안 되므로 예외를 삼킨다.
    """
    technique_id = chain.get("technique_id") if isinstance(chain, dict) else None
    if not technique_id or not TECHNIQUE_ID_RE.match(technique_id):
        return
    now = datetime.now(timezone.utc)
    try:
        _insert_execution_log(
            round_id=round_id,
            chain_id=uuid.uuid4(),
            technique=technique_id,
            channel=CHANNEL,
            success=False,
            started_at=now,
            finished_at=now,
            container_id=BLOCKED_CONTAINER_ID,
        )
    except Exception as exc:
        logger.warning("차단된 시도의 execution_log 기록 실패 (round_id=%s, decision=%s): %s", round_id, decision, exc)


def _notify_scenario_review(chain: dict, source: str, review_result: dict) -> dict:
    try:
        from purplebpf.offensive.review.slack_notify import notify_scenario_review

        return notify_scenario_review(chain, source, review_result)
    except Exception:
        return {"type": "SLACK", "status": "FAILED"}


def decide_execution(
    validation_results: Sequence[str | None], allow_review: bool = False
) -> dict:
    """Apply the fail-closed execution policy without changing validator verdicts."""
    statuses = tuple(validation_results)
    if not statuses or any(status not in _KNOWN_EXECUTION_STATUSES for status in statuses):
        validation_status = "ERROR"
        execution_allowed = False
    elif "ERROR" in statuses:
        validation_status = "ERROR"
        execution_allowed = False
    elif "REJECT" in statuses or "FAIL" in statuses:
        validation_status = "REJECT" if "REJECT" in statuses else "FAIL"
        execution_allowed = False
    elif "REVIEW" in statuses:
        validation_status = "REVIEW"
        execution_allowed = allow_review
    else:
        validation_status = "PASS"
        execution_allowed = True

    review_override = validation_status == "REVIEW" and execution_allowed
    return {
        "validation_status": validation_status,
        "execution_allowed": execution_allowed,
        "execution_policy": (
            DEMO_ALLOW_REVIEW_POLICY
            if review_override
            else STANDARD_EXECUTION_POLICY
        ),
        "review_override": review_override,
    }


def execute_chain(
    chain: dict, round_id: int = 1, allow_review: bool = False
) -> dict:
    gate = _validate_execution_gate(chain)
    policy = decide_execution((gate["decision"],), allow_review=allow_review)
    notification = None
    if gate["decision"] == "REVIEW":
        notification = _notify_scenario_review(
            chain, "RULE_VALIDATOR", gate["validation"]
        )

    if not policy["execution_allowed"]:
        if gate["decision"] in ("REVIEW", "FAIL"):
            _log_blocked_attempt(round_id, chain, gate["decision"])
        result = {
            "status": "ERROR" if gate["decision"] == "ERROR" else "SKIPPED",
            "decision": gate["decision"],
            "success": False,
            "blocked_by": "RULE_VALIDATOR",
            "reason": gate["reason"],
            "step_results": [],
            **(
                {"validation": gate["validation"]}
                if "validation" in gate
                else {}
            ),
            **({"error": gate["error"]} if "error" in gate else {}),
            **policy,
        }
        if notification is not None:
            result["notification"] = notification
        return result

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

    record = dict(
        _insert_execution_log(
            round_id=round_id,
            chain_id=chain_id,
            technique=technique_id,
            channel=CHANNEL,
            success=success,
            started_at=started_at,
            finished_at=finished_at,
            container_id=container_id,
        )
    )
    record["step_results"] = step_results
    record.update(policy)
    if "validation" in gate:
        record["validation"] = gate["validation"]
    if notification is not None:
        record["notification"] = notification
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


def _cli_error(reason: str, error: Exception | str) -> dict:
    message = str(error)
    return {
        "status": "ERROR",
        "decision": "ERROR",
        "success": False,
        "blocked_by": None,
        "reason": reason,
        "error": message,
        "step_results": [],
    }


def _first_filter_blocked_result(verdict: dict, allow_review: bool = False) -> dict:
    verdict_status = verdict.get("verdict")
    if verdict_status == "REVIEW":
        status = "SKIPPED"
        decision = "REVIEW"
        reason = "FIRST_FILTER_REVIEW"
    elif verdict_status == "REJECT":
        status = "SKIPPED"
        decision = "FAIL"
        reason = "FIRST_FILTER_REJECTED"
    else:
        status = "ERROR"
        decision = "ERROR"
        reason = "FIRST_FILTER_RESULT_INVALID"
    return {
        "status": status,
        "decision": decision,
        "success": False,
        "blocked_by": "FIRST_FILTER",
        "reason": reason,
        "first_filter": verdict,
        "step_results": [],
        **decide_execution((verdict_status,), allow_review=allow_review),
    }


def _normalize_execution_result(result: dict, verdict: dict) -> dict:
    if not isinstance(result, dict):
        return {
            **_cli_error("EXECUTOR_RESULT_INVALID", "Executor returned a non-object result"),
            "blocked_by": "RULE_VALIDATOR",
            "first_filter": verdict,
        }

    normalized = dict(result)
    if "decision" in normalized:
        normalized.setdefault("blocked_by", "RULE_VALIDATOR")
    else:
        normalized.update(
            {
                "status": "EXECUTED",
                "decision": "PASS",
                "blocked_by": None,
            }
        )
    normalized["first_filter"] = verdict
    return normalized


def _exit_code_for_result(result: dict) -> int:
    decision = result.get("decision")
    if decision == "REVIEW":
        return EXIT_REVIEW
    if decision == "FAIL":
        return EXIT_REJECTED
    if decision == "ERROR" or result.get("status") == "ERROR":
        return EXIT_SYSTEM_ERROR
    if result.get("status") == "EXECUTED" and decision == "PASS":
        return EXIT_SUCCESS if result.get("success") is True else EXIT_EXECUTION_FAILED
    return EXIT_SYSTEM_ERROR


def _print_cli_result(result: dict) -> None:
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


# 실행 후 아래 SELECT로 execution_log에 행이 들어갔는지 확인할 수 있다:
#
#   SELECT run_id, round_id, chain_id, technique, channel, success,
#          started_at, finished_at, container_id, created_at
#   FROM execution_log
#   ORDER BY run_id DESC
#   LIMIT 5;


def main(argv: Sequence[str] | None = None) -> int:
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
    parser.add_argument(
        "--chain-file",
        help="체인 JSON 파일. 지정하면 Neo4j·gemma 생성을 건너뛴다 "
        "(0라운드 씨앗 체인이나 룰팩 검증용)",
    )
    parser.add_argument(
        "--allow-review",
        action="store_true",
        help="초기 MVP 데모에서 REVIEW 판정을 유지한 채 실행을 허용한다",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_SUCCESS if exc.code == 0 else EXIT_INVALID_INPUT

    if args.chain_file:
        try:
            chain = json.loads(Path(args.chain_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result = _cli_error("SCENARIO_INPUT_ERROR", exc)
            _print_cli_result(result)
            return EXIT_INVALID_INPUT
    else:
        try:
            from purplebpf.offensive.generation.generator import generate_chain

            chain = generate_chain(args.technique_id)
        except Exception as exc:
            result = _cli_error("SCENARIO_GENERATION_ERROR", exc)
            _print_cli_result(result)
            return EXIT_SYSTEM_ERROR

    try:
        from purplebpf.offensive.filter.first_filter import filter_chain

        verdict = filter_chain(chain)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        result = _cli_error("SCENARIO_INPUT_ERROR", exc)
        _print_cli_result(result)
        return EXIT_INVALID_INPUT
    except Exception as exc:
        result = _cli_error("FIRST_FILTER_ERROR", exc)
        _print_cli_result(result)
        return EXIT_SYSTEM_ERROR

    verdict_status = verdict.get("verdict") if isinstance(verdict, dict) else None
    first_filter_policy = decide_execution(
        (verdict_status,), allow_review=args.allow_review
    )
    first_filter_notification = None
    if verdict_status == "REVIEW":
        first_filter_notification = _notify_scenario_review(
            chain, "FIRST_FILTER", verdict
        )

    if not first_filter_policy["execution_allowed"]:
        if verdict_status in ("REVIEW", "REJECT"):
            _log_blocked_attempt(args.round_id, chain, verdict_status)
        result = _first_filter_blocked_result(
            verdict if isinstance(verdict, dict) else {"verdict": None},
            allow_review=args.allow_review,
        )
        if first_filter_notification is not None:
            result["notification"] = first_filter_notification
        _print_cli_result(result)
        return _exit_code_for_result(result)

    try:
        execution_result = execute_chain(
            chain,
            round_id=args.round_id,
            allow_review=args.allow_review,
        )
    except Exception as exc:
        result = _cli_error("EXECUTOR_ERROR", exc)
        result["first_filter"] = verdict
        _print_cli_result(result)
        return EXIT_SYSTEM_ERROR

    result = _normalize_execution_result(execution_result, verdict)
    executor_validation_status = result.get("validation_status")
    if executor_validation_status is None:
        executor_validation_status = (
            "PASS" if result.get("status") == "EXECUTED" else result.get("decision")
        )
    result.update(
        decide_execution(
            (verdict_status, executor_validation_status),
            allow_review=args.allow_review,
        )
    )
    if first_filter_notification is not None:
        result["first_filter_notification"] = first_filter_notification
    _print_cli_result(result)
    return _exit_code_for_result(result)


if __name__ == "__main__":
    raise SystemExit(main())
