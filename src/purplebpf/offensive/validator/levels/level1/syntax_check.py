import json
import subprocess
from typing import Any


SHELLCHECK_TIMEOUT_SECONDS = 10
FAIL_SEVERITIES = {"error", "warning"}


def _tool_error(message: str, exit_code: int | None = None) -> dict[str, Any]:
    return {
        "passed": False,
        "exit_code": exit_code,
        "diagnostics": "",
        "diagnostic_items": [],
        "tool_error": message,
    }


def check_shell_syntax(command: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["shellcheck", "-s", "bash", "--format=json", "-"],
            input=command,
            text=True,
            capture_output=True,
            timeout=SHELLCHECK_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return _tool_error("shellcheck binary was not found")
    except subprocess.TimeoutExpired:
        return _tool_error("shellcheck execution timed out")
    except OSError as exc:
        return _tool_error(f"shellcheck execution failed: {exc}")

    diagnostics_text = result.stdout.strip()
    if result.returncode not in {0, 1}:
        message = result.stderr.strip() or diagnostics_text or "unknown tool error"
        return _tool_error(
            f"shellcheck exited abnormally: {message}", result.returncode
        )

    try:
        diagnostic_items = json.loads(diagnostics_text or "[]")
    except json.JSONDecodeError as exc:
        return _tool_error(
            f"failed to parse shellcheck JSON output: {exc.msg}",
            result.returncode,
        )
    if not isinstance(diagnostic_items, list) or not all(
        isinstance(item, dict) for item in diagnostic_items
    ):
        return _tool_error(
            "shellcheck JSON output was not a diagnostic list", result.returncode
        )

    passed = not any(
        item.get("level") in FAIL_SEVERITIES for item in diagnostic_items
    )

    return {
        "passed": passed,
        "exit_code": result.returncode,
        "diagnostics": diagnostics_text,
        "diagnostic_items": diagnostic_items,
        "tool_error": None,
    }
