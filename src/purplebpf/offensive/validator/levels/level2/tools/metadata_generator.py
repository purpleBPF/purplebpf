"""Generate reviewable CLI metadata candidates from local documentation only."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENERATOR_VERSION = "1"
_COMMAND_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*")
_OPTION_NAME = re.compile(
    r"(?<![A-Za-z0-9])(--[A-Za-z0-9][A-Za-z0-9-]*|-[A-Za-z0-9?]+)"
)
_VALUE_TOKEN = re.compile(
    r"<([^>]+)>|\[=([A-Za-z][A-Za-z0-9_.:/-]*)\]"
    r"|=([A-Za-z][A-Za-z0-9_.:/-]*)|\s([A-Z][A-Z0-9_.:/-]*)"
)


def _run_documentation(
    argv: list[str], timeout: float
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {"LANG": "C", "LC_ALL": "C", "MANPAGER": "cat", "PAGER": "cat"}
    )
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=environment,
    )


def _clean_man_text(value: str) -> str:
    return re.sub(r".\x08", "", value)


def _synopsis(documentation: str) -> str | None:
    for line in documentation.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("usage:"):
            return stripped
    return None


def _option_area(line: str) -> str | None:
    stripped = line.strip()
    if not stripped.startswith("-"):
        return None
    description = re.search(r"\s{2,}(?=[a-z(])", stripped)
    return stripped[: description.start()] if description else stripped


def extract_options(documentation: str) -> list[dict[str, Any]]:
    """Extract conservative option candidates from help/man text."""
    options: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for line in documentation.splitlines():
        area = _option_area(line)
        if area is None:
            continue
        names = []
        for name in _OPTION_NAME.findall(area):
            if name not in names:
                names.append(name)
        if not names:
            continue
        key = tuple(names)
        if key in seen:
            continue
        seen.add(key)

        option: dict[str, Any] = {"names": names}
        value_match = _VALUE_TOKEN.search(area)
        if value_match is not None:
            value_name = next(
                group for group in value_match.groups() if group is not None
            )
            option["value"] = (
                "optional_attached"
                if "[=" in value_match.group(0)
                else "required"
            )
            option["value_name"] = value_name
        options.append(option)
    return options


def _version(executable: str, timeout: float) -> str | None:
    try:
        result = _run_documentation([executable, "--version"], timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = result.stdout or result.stderr
    return output.splitlines()[0].strip() if output.strip() else None


def _failure(command: str, code: str, message: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "command": command,
        "generated": False,
        "code": code,
        "message": message,
        "review_status": "PENDING",
        "provenance": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator_version": GENERATOR_VERSION,
        },
    }


def generate_candidate(command: str, *, timeout: float = 5.0) -> dict[str, Any]:
    """Generate a PENDING candidate without running the command's operation."""
    if _COMMAND_NAME.fullmatch(command) is None:
        return _failure(command, "INVALID_COMMAND_NAME", "command must be a basename")
    executable = shutil.which(command)
    if executable is None:
        return _failure(
            command,
            "LOCAL_COMMAND_NOT_FOUND",
            "command is not installed in the local development environment",
        )

    attempts: list[dict[str, Any]] = []
    sources = [
        ("help", [executable, "--help"]),
        ("man", ["man", command]),
    ]
    for source_type, argv in sources:
        try:
            result = _run_documentation(argv, timeout)
        except subprocess.TimeoutExpired:
            attempts.append({"type": source_type, "code": "TIMEOUT"})
            continue
        except OSError as exc:
            attempts.append(
                {"type": source_type, "code": "UNAVAILABLE", "message": str(exc)}
            )
            continue

        documentation = _clean_man_text(result.stdout or result.stderr)
        options = extract_options(documentation)
        attempts.append(
            {
                "type": source_type,
                "exit_code": result.returncode,
                "option_count": len(options),
            }
        )
        if not options:
            continue
        version_supported = any(
            "--version" in option["names"] for option in options
        )
        return {
            "schema_version": 1,
            "command": command,
            "generated": True,
            "source": {
                "type": source_type,
                "command": argv,
                "exit_code": result.returncode,
            },
            "version": _version(executable, timeout) if version_supported else None,
            "synopsis": _synopsis(documentation),
            "metadata": {"operands": {}, "options": options},
            "review_status": "PENDING",
            "provenance": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator_version": GENERATOR_VERSION,
            },
            "warnings": [
                "operand bounds and roles were not inferred automatically",
                "candidate metadata is not loaded by the runtime provider",
            ],
            "attempts": attempts,
        }

    failure = _failure(
        command,
        "METADATA_EXTRACTION_FAILED",
        "local help and man documentation did not yield option metadata",
    )
    failure["attempts"] = attempts
    return failure


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="+")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    candidates = [
        generate_candidate(command, timeout=args.timeout) for command in args.command
    ]
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for candidate in candidates:
            path = args.output_dir / f"{candidate['command']}.json"
            path.write_text(
                json.dumps(candidate, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    print(
        json.dumps(
            candidates[0] if len(candidates) == 1 else candidates,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
