"""CLI and reusable orchestration for Scenario Validator Levels 1-3."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .levels.level1.syntax_check import check_shell_syntax
from .levels.level2.validator import validate_scenario as validate_level2
from .levels.level3.validator import validate_scenario as validate_level3


def _validate_input(scenario: Any) -> dict[str, Any]:
    if not isinstance(scenario, dict):
        raise ValueError("scenario must be a JSON object")
    steps = scenario.get("steps")
    if not isinstance(steps, list):
        raise ValueError("scenario.steps must be a JSON array")
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError(f"scenario.steps[{index}] must be a JSON object")
        if "order" not in step:
            raise ValueError(f"scenario.steps[{index}].order is required")
        if not isinstance(step.get("command"), str):
            raise ValueError(
                f"scenario.steps[{index}].command must be a string"
            )
    return scenario


def _validate_level1(scenario: dict[str, Any]) -> dict[str, Any]:
    steps = []
    passed = True
    tool_failed = False
    for step in scenario["steps"]:
        result = check_shell_syntax(step["command"])
        passed = passed and result["passed"]
        tool_failed = tool_failed or result.get("tool_error") is not None
        steps.append(
            {
                "order": step["order"],
                "command": step["command"],
                "passed": result["passed"],
                "exit_code": result["exit_code"],
                "diagnostics": result["diagnostics"],
                "diagnostic_items": result.get("diagnostic_items", []),
                "tool_error": result.get("tool_error"),
            }
        )
    return {
        "level": 1,
        "check": "shell_syntax",
        "status": "ERROR" if tool_failed else "PASS" if passed else "FAIL",
        "steps": steps,
    }


def _result(
    scenario: dict[str, Any],
    level1: dict[str, Any] | None,
    level2: dict[str, Any] | None,
    level3: dict[str, Any] | None,
    *,
    final: dict[str, Any],
) -> dict[str, Any]:
    return {
        "scenario": {
            "technique_id": scenario.get("technique_id"),
            "step_count": len(scenario["steps"]),
        },
        "level1": level1,
        "level2": level2,
        "level3": level3,
        "final": final,
    }


def _level_status(level: dict[str, Any] | None) -> str | None:
    return level.get("status") if isinstance(level, dict) else None


def _final(status: str, stopped_at: str | None, reason: str) -> dict[str, Any]:
    return {"status": status, "stopped_at": stopped_at, "reason": reason}


def aggregate_validation_status(
    level1: dict[str, Any] | None,
    level2: dict[str, Any] | None,
    level3: dict[str, Any] | None,
) -> dict[str, Any]:
    """Aggregate Levels 1-3 while recognizing valid early-stop shapes."""
    level1_status = _level_status(level1)
    level2_status = _level_status(level2)
    level3_status = _level_status(level3)

    if level1_status == "ERROR" and level2 is None and level3 is None:
        return _final("ERROR", "level1", "LEVEL1_ERROR")
    if level1_status == "FAIL" and level2 is None and level3 is None:
        return _final("REJECT", "level1", "LEVEL1_SYNTAX_FAILURE")
    if level1_status != "PASS":
        return _final("ERROR", "level1", "VALIDATION_RESULT_INVALID")

    if level2_status == "ERROR" and level3 is None:
        return _final("ERROR", "level2", "LEVEL2_ERROR")
    if level2_status in {"FAIL", "REJECT"} and level3 is None:
        return _final("REJECT", "level2", "LEVEL2_REJECT")
    if level2_status not in {"PASS", "REVIEW"}:
        return _final("ERROR", "level2", "VALIDATION_RESULT_INVALID")

    if level3_status == "ERROR":
        return _final("ERROR", "level3", "LEVEL3_ERROR")
    if level3_status in {"FAIL", "REJECT"}:
        return _final("REJECT", None, "LEVEL3_REJECT")
    if level3_status not in {"PASS", "REVIEW"}:
        return _final("ERROR", "level3", "VALIDATION_RESULT_INVALID")

    if level2_status == "REVIEW":
        return _final("REVIEW", None, "LEVEL2_REVIEW")
    if level3_status == "REVIEW":
        return _final("REVIEW", None, "LEVEL3_REVIEW")
    return _final("PASS", None, "LEVEL3_CORE_MATCH")


def _exception_level(level: int, exc: Exception) -> dict[str, Any]:
    return {
        "level": level,
        "status": "ERROR",
        "errors": [
            {
                "code": f"LEVEL{level}_ERROR",
                "message": f"{type(exc).__name__}: {exc}",
            }
        ],
    }


def validate_scenario_pipeline(scenario: dict[str, Any]) -> dict[str, Any]:
    """Run Level 1, Level 2, and Level 3 using the integration gate policy."""
    scenario = _validate_input(scenario)
    try:
        level1_result = _validate_level1(scenario)
    except Exception as exc:
        level1_result = _exception_level(1, exc)
    if level1_result["status"] != "PASS":
        return _result(
            scenario,
            level1_result,
            None,
            None,
            final=aggregate_validation_status(level1_result, None, None),
        )

    try:
        level2_result = validate_level2(scenario)
    except Exception as exc:
        level2_result = _exception_level(2, exc)
    if level2_result["status"] not in {"PASS", "REVIEW"}:
        return _result(
            scenario,
            level1_result,
            level2_result,
            None,
            final=aggregate_validation_status(level1_result, level2_result, None),
        )

    try:
        level3_result = validate_level3(
            scenario,
            level2_output=level2_result,
        )
    except Exception as exc:
        level3_result = _exception_level(3, exc)
    return _result(
        scenario,
        level1_result,
        level2_result,
        level3_result,
        final=aggregate_validation_status(
            level1_result, level2_result, level3_result
        ),
    )


def _print_cli_error(code: str, message: str) -> None:
    print(
        json.dumps(
            {"error": {"code": code, "message": message}},
            ensure_ascii=False,
        ),
        file=sys.stderr,
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        _print_cli_error(
            "INVALID_ARGUMENT",
            "usage: python -m purplebpf.offensive.validator.main <scenario.json>",
        )
        return 2

    scenario_path = Path(arguments[0])
    try:
        with scenario_path.open(encoding="utf-8") as scenario_file:
            scenario = json.load(scenario_file)
    except json.JSONDecodeError as exc:
        _print_cli_error(
            "INVALID_JSON",
            f"failed to parse {scenario_path}: {exc.msg}",
        )
        return 2
    except OSError as exc:
        _print_cli_error(
            "SCENARIO_FILE_ERROR",
            f"failed to read {scenario_path}: {exc}",
        )
        return 2

    try:
        output = validate_scenario_pipeline(scenario)
    except (TypeError, ValueError, KeyError) as exc:
        _print_cli_error("INVALID_SCENARIO", str(exc))
        return 2

    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
