"""Parse shell text into one or more executable/argv invocations.

This module deliberately stops at shell parsing. It does not assign semantic
roles (option, option value, operand) to any arguments. ``parse_command`` keeps
the original single-command contract while ``extract_command_invocations``
supports lists, pipelines, and bounded bash/sh ``-c`` recursion.
"""

from __future__ import annotations

import os
from typing import Any

import bashlex


class CommandParseError(ValueError):
    """Raised when a command is invalid or outside the supported shell subset."""


MAX_NESTED_SHELL_DEPTH = 3
_SHELL_INTERPRETERS = {"bash", "sh"}
_SIMPLE_REDIRECTS = {">", ">>", "<"}


def _parse_redirect(part: Any, source: str) -> dict[str, Any]:
    redirect_type = getattr(part, "type", None)
    if redirect_type not in _SIMPLE_REDIRECTS:
        raise CommandParseError(
            f"unsupported shell redirect: {redirect_type}"
        )
    if getattr(part, "input", None) is not None:
        raise CommandParseError("explicit file-descriptor redirects are unsupported")

    target = getattr(part, "output", None)
    if target is None or target.kind != "word" or getattr(target, "parts", None):
        raise CommandParseError("dynamic shell redirect targets are unsupported")
    start, end = part.pos
    return {
        "operator": redirect_type,
        "target": target.word,
        "raw": source[start:end],
    }


def _parse_command_node(command_node: Any, source: str) -> dict[str, Any]:
    if command_node.kind != "command":
        raise CommandParseError(
            f"unsupported shell structure: {command_node.kind}"
        )

    words: list[str] = []
    redirects: list[dict[str, Any]] = []
    for part in command_node.parts:
        if part.kind == "redirect":
            redirects.append(_parse_redirect(part, source))
            continue
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

    start, end = command_node.pos
    result = {
        "raw_command": source[start:end],
        "executable": {
            "raw": executable_raw,
            "normalized": executable_normalized,
        },
        "argv": words[1:],
    }
    if redirects:
        result["redirects"] = redirects
    return result


def _nested_shell_source(invocation: dict[str, Any]) -> str | None:
    executable = invocation["executable"]["normalized"]
    argv = invocation["argv"]
    if executable not in _SHELL_INTERPRETERS or "-c" not in argv:
        return None
    option_index = argv.index("-c")
    if option_index + 1 >= len(argv):
        return None
    return argv[option_index + 1]


def _extract_level(
    source: str,
    *,
    depth: int,
    max_depth: int,
) -> dict[str, Any]:
    try:
        nodes = bashlex.parse(source)
    except Exception as exc:
        raise CommandParseError(f"failed to parse shell command: {exc}") from exc

    commands: list[dict[str, Any]] = []

    def visit(node: Any, operator_before: str | None = None) -> None:
        if node.kind == "command":
            invocation = _parse_command_node(node, source)
            invocation["operator_before"] = operator_before
            commands.append(invocation)
            return

        if node.kind not in {"list", "pipeline"}:
            raise CommandParseError(f"unsupported shell structure: {node.kind}")

        pending_operator = operator_before
        for part in node.parts:
            if part.kind == "operator":
                if part.op not in {"&&", "||", ";"}:
                    raise CommandParseError(
                        f"unsupported shell operator: {part.op}"
                    )
                pending_operator = part.op
            elif part.kind == "pipe":
                pending_operator = "|"
            else:
                visit(part, pending_operator)
                pending_operator = None

    for node_index, node in enumerate(nodes):
        visit(node, ";" if node_index else None)

    if not commands:
        raise CommandParseError("command does not contain a valid executable")

    for index, invocation in enumerate(commands, start=1):
        invocation["index"] = index
        nested_source = _nested_shell_source(invocation)
        if nested_source is None:
            continue
        if depth >= max_depth:
            invocation["nested_truncated"] = True
            continue
        try:
            nested = _extract_level(
                nested_source,
                depth=depth + 1,
                max_depth=max_depth,
            )
        except CommandParseError as exc:
            raise CommandParseError(
                f"failed to parse nested shell command at depth {depth + 1}: {exc}"
            ) from exc
        invocation["nested_commands"] = nested["commands"]
        invocation["nested_operators"] = nested["operators"]

    operators = []
    for invocation in commands:
        operator = invocation["operator_before"]
        if operator is None:
            continue
        operators.append(
            {
                "operator": operator,
                "left_index": invocation["index"] - 1,
                "right_index": invocation["index"],
            }
        )

    return {
        "raw_command": source,
        "depth": depth,
        "commands": commands,
        "operators": operators,
    }


def extract_command_invocations(
    command: str,
    *,
    max_depth: int = MAX_NESTED_SHELL_DEPTH,
) -> dict[str, Any]:
    """Extract command invocations without guessing argument semantics.

    Supported composition is limited to ``&&``, ``||``, ``;``, and ``|``.
    Only bash/sh ``-c`` payloads are recursively parsed. Other interpreter
    payloads remain ordinary argv values.
    """
    if not isinstance(command, str):
        raise CommandParseError("command must be a string")
    if not command.strip():
        raise CommandParseError("command must not be empty")
    if not isinstance(max_depth, int) or max_depth < 0:
        raise CommandParseError("max_depth must be a non-negative integer")
    return _extract_level(command, depth=0, max_depth=max_depth)


def parse_command(command: str) -> dict[str, Any]:
    """Parse one simple shell command and return its executable and argv.

    Supported commands consist of shell words and simple file redirects. Shell
    control structures, pipelines, assignments, expansions, and complex
    redirects are rejected rather than being interpreted incompletely.
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
    return _parse_command_node(command_node, command)
