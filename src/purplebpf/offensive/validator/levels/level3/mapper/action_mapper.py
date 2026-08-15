"""Map Level 2 structured commands to standard Actions and Context."""

from __future__ import annotations

import json
import re
from typing import Any

from .action_rule_provider import ActionRuleError, JsonActionRuleProvider


UNMAPPED_ACTION = "UNMAPPED_ACTION"


def _operands(level2_result: dict[str, Any]) -> dict[int, str]:
    return {
        element["position"]: element["raw"]
        for element in level2_result.get("elements", [])
        if element.get("type") == "operand"
    }


def _resources(
    level2_result: dict[str, Any], direction: str
) -> list[dict[str, Any]]:
    return level2_result.get("resources", {}).get(direction, [])


def _path_group(path: Any, path_groups: dict[str, list[str]]) -> str | None:
    if not isinstance(path, str):
        return None
    for name, prefixes in path_groups.items():
        if any(path.startswith(prefix) for prefix in prefixes):
            return name
    return None


def _lookup(state: dict[str, Any], reference: str) -> Any:
    value: Any = state
    for part in reference.split("."):
        if not isinstance(value, dict):
            return None
        key: Any = int(part) if part.isdigit() and int(part) in value else part
        if key not in value:
            return None
        value = value[key]
    return value


def _matches(
    rule: dict[str, Any],
    level2_result: dict[str, Any],
    path_groups: dict[str, list[str]],
) -> dict[str, Any] | None:
    match = rule.get("match", {})
    executable = level2_result.get("executable", {})
    normalized = executable.get("normalized")
    raw = executable.get("raw")

    if "executable" in match and normalized != match["executable"]:
        return None
    if "executable_in" in match and normalized not in match["executable_in"]:
        return None
    if "executable_path_prefix_group" in match and _path_group(
        raw, path_groups
    ) != match["executable_path_prefix_group"]:
        return None

    operands = _operands(level2_result)
    operand_match = match.get("operand")
    if operand_match is not None:
        operand = operands.get(operand_match["position"])
        if operand is None or re.search(operand_match["regex"], operand) is None:
            return None

    state: dict[str, Any] = {
        "executable": executable,
        "operand": operands,
    }
    resource_match = match.get("resource")
    if resource_match is not None:
        matched_resource = next(
            (
                resource
                for resource in _resources(
                    level2_result, resource_match["direction"]
                )
                if resource.get("type") == resource_match["type"]
            ),
            None,
        )
        if matched_resource is None:
            return None
        state["matched_resource"] = matched_resource
    return state


def _iterations(
    rule: dict[str, Any], level2_result: dict[str, Any]
) -> list[dict[str, Any]]:
    iterate = rule.get("iterate")
    if iterate is None:
        return [{}]

    if "options" in iterate:
        values = iterate["options"]["values"]
        return [
            {"option": element["raw"], "value": values[element["raw"]]}
            for element in level2_result.get("elements", [])
            if element.get("type") == "option" and element.get("raw") in values
        ]

    resource_spec = iterate["resources"]
    return [
        {"resource": resource}
        for resource in _resources(level2_result, resource_spec["direction"])
        if resource.get("type") == resource_spec["type"]
    ]


def _resolve_value(
    specification: dict[str, Any],
    state: dict[str, Any],
    path_groups: dict[str, list[str]],
) -> Any:
    if "const" in specification:
        return specification["const"]
    if "from" in specification:
        return _lookup(state, specification["from"])
    if "path_group_of" in specification:
        path = _lookup(state, specification["path_group_of"]["from"])
        return _path_group(path, path_groups)
    return None


def _emit_action(
    rule: dict[str, Any],
    match_state: dict[str, Any],
    iteration: dict[str, Any],
    path_groups: dict[str, list[str]],
    action_vocabulary: set[str],
    context_vocabulary: set[str],
) -> dict[str, Any]:
    emit = rule["emit"]
    action = emit["action"]
    if action not in action_vocabulary:
        raise ActionRuleError(f"unknown Action in rule {rule['id']}: {action}")

    state = {**match_state, "iteration": iteration}
    context: dict[str, Any] = {}
    for key, specification in emit.get("context", {}).items():
        if key not in context_vocabulary:
            raise ActionRuleError(f"unknown Context in rule {rule['id']}: {key}")
        value = _resolve_value(specification, state, path_groups)
        if value is not None:
            context[key] = value

    evidence = {
        key: value
        for key, specification in emit.get("evidence", {}).items()
        if (value := _resolve_value(specification, state, path_groups)) is not None
    }
    return {"action": action, "context": context, "evidence": evidence}


def map_actions(
    level2_result: dict[str, Any],
    rule_provider: JsonActionRuleProvider | None = None,
) -> dict[str, Any]:
    """Map one Level 2 command result without using ATT&CK Technique metadata."""
    provider = rule_provider or JsonActionRuleProvider()
    document = provider.get_document()
    path_groups = document["path_groups"]
    action_vocabulary = set(document["action_vocabulary"])
    context_vocabulary = set(document["context_vocabulary"])
    actions: list[dict[str, Any]] = []
    seen: set[str] = set()

    for rule in document["rules"]:
        match_state = _matches(rule, level2_result, path_groups)
        if match_state is None:
            continue
        for iteration in _iterations(rule, level2_result):
            action = _emit_action(
                rule,
                match_state,
                iteration,
                path_groups,
                action_vocabulary,
                context_vocabulary,
            )
            key = json.dumps(action, sort_keys=True, separators=(",", ":"))
            if key not in seen:
                seen.add(key)
                actions.append(action)

    return {
        "raw_command": level2_result.get("raw_command"),
        "executable": level2_result.get("executable"),
        "actions": actions,
        "action_validation": {
            "mapped": bool(actions),
            "code": None if actions else UNMAPPED_ACTION,
        },
    }
