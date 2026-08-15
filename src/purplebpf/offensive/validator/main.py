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
    for step in scenario["steps"]:
        result = check_shell_syntax(step["command"])
        passed = passed and result["passed"]
        steps.append(
            {
                "order": step["order"],
                "command": step["command"],
                "passed": result["passed"],
                "exit_code": result["exit_code"],
                "diagnostics": result["diagnostics"],
            }
        )
    return {
        "level": 1,
        "check": "shell_syntax",
        "status": "PASS" if passed else "FAIL",
        "steps": steps,
    }


def _result(
    scenario: dict[str, Any],
    level1: dict[str, Any],
    level2: dict[str, Any] | None,
    level3: dict[str, Any] | None,
    *,
    status: str,
    stopped_at: str | None,
    reason: str,
) -> dict[str, Any]:
    return {
        "scenario": {
            "technique_id": scenario.get("technique_id"),
            "step_count": len(scenario["steps"]),
        },
        "level1": level1,
        "level2": level2,
        "level3": level3,
        "final": {
            "status": status,
            "stopped_at": stopped_at,
            "reason": reason,
        },
    }


def validate_scenario_pipeline(scenario: dict[str, Any]) -> dict[str, Any]:
    """Run Level 1, Level 2, and Level 3 using the integration gate policy."""
    scenario = _validate_input(scenario)
    level1_result = _validate_level1(scenario)
    if level1_result["status"] != "PASS":
        return _result(
            scenario,
            level1_result,
            None,
            None,
            status="REJECT",
            stopped_at="level1",
            reason="LEVEL1_SYNTAX_FAILURE",
        )

    level2_result = validate_level2(scenario)
    if level2_result["status"] == "REJECT":
        return _result(
            scenario,
            level1_result,
            level2_result,
            None,
            status="REJECT",
            stopped_at="level2",
            reason="LEVEL2_REJECT",
        )

    level3_result = validate_level3(
        scenario,
        level2_output=level2_result,
    )
    level3_status = level3_result["status"]
    reason = {
        "PASS": "LEVEL3_CORE_MATCH",
        "REVIEW": "LEVEL3_REVIEW",
        "REJECT": "LEVEL3_REJECT",
    }[level3_status]
    return _result(
        scenario,
        level1_result,
        level2_result,
        level3_result,
        status=level3_status,
        stopped_at=None,
        reason=reason,
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
