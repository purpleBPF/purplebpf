"""Parse a single, simple shell command into an executable and argv.

This module deliberately stops at shell parsing.  It does not assign semantic
roles (option, option value, operand) to any arguments.
"""

from __future__ import annotations

import os
from typing import Any

import bashlex


class CommandParseError(ValueError):
    """Raised when a command is invalid or outside the supported shell subset."""


def parse_command(command: str) -> dict[str, Any]:
    """Parse one simple shell command and return its executable and argv.

    Supported commands consist only of shell words.  Shell control structures,
    pipelines, redirects, assignments, and expansions are rejected rather than
    being interpreted incompletely.
    """
    if not isinstance(command, str):
        raise CommandParseError("command must be a string")
    if not command.strip():
        raise CommandParseError("command must not be empty")

    try:
        nodes = bashlex.parse(command)
    except Exception as exc:
        raise CommandParseError(f"failed to parse shell command: {exc}") from exc

    if len(nodes) != 1:
        raise CommandParseError(
            "unsupported shell structure: expected exactly one command"
        )

    command_node = nodes[0]
    if command_node.kind != "command":
        raise CommandParseError(
            f"unsupported shell structure: {command_node.kind}"
        )

    words: list[str] = []
    for part in command_node.parts:
        if part.kind != "word":
            raise CommandParseError(
                f"unsupported shell structure in command: {part.kind}"
            )
        if getattr(part, "parts", None):
            nested_kinds = ", ".join(nested.kind for nested in part.parts)
            raise CommandParseError(
                f"unsupported shell expansion in word: {nested_kinds}"
            )
        words.append(part.word)

    if not words or not words[0]:
        raise CommandParseError("command does not contain a valid executable")

    executable_raw = words[0]
    executable_normalized = os.path.basename(executable_raw)
    if not executable_normalized:
        raise CommandParseError("command does not contain a valid executable")

    return {
        "raw_command": command,
        "executable": {
            "raw": executable_raw,
            "normalized": executable_normalized,
        },
        "argv": words[1:],
    }
