"""Public entry points for command and scenario Level 2 validation."""

from __future__ import annotations

import json
from typing import Any

from .engine.chain_validator import validate_dependencies
from .engine.resource_mapper import JsonResourceRuleProvider, map_resources
from .engine.semantic_mapper import JsonSemanticRuleProvider, map_facts
from .parser.argument_mapper import map_arguments
from .parser.command_parser import (
    MAX_NESTED_SHELL_DEPTH,
    CommandParseError,
    extract_command_invocations,
    parse_command,
)
from .parser.metadata_provider import JsonMetadataProvider, MetadataProvider
from .support_tier import resolve_support_tier


def _analyze_parsed_command(
    parsed: dict[str, Any],
    metadata_provider: MetadataProvider | None = None,
    resource_rule_provider: JsonResourceRuleProvider | None = None,
    semantic_rule_provider: JsonSemanticRuleProvider | None = None,
) -> dict[str, Any]:
    metadata = metadata_provider or JsonMetadataProvider()
    semantics_provider = semantic_rule_provider or JsonSemanticRuleProvider()
    result = map_arguments(parsed, metadata)
    result["support_tier"] = resolve_support_tier(
        result["executable"]["normalized"], metadata, semantics_provider
    )
    if result["cli_validation"]["valid"] is True:
        resources = map_resources(result, resource_rule_provider)
        semantics = map_facts(result, semantics_provider)
    else:
        resources = {
            "requires": [],
            "produces": [],
            "resource_validation": {"resolved": None, "code": None},
        }
        semantics = {
            "facts": [],
            "fact_validation": {"resolved": None, "code": None},
        }
    result["resources"] = {
        "requires": resources["requires"],
        "produces": resources["produces"],
    }
    result["resource_validation"] = resources["resource_validation"]
    result["facts"] = semantics["facts"]
    result["fact_validation"] = semantics["fact_validation"]
    cli_valid = result["cli_validation"]["valid"]
    result["analysis"] = {
        "support_tier": result["support_tier"],
        "cli": "validated" if cli_valid is True else (
            "invalid" if cli_valid is False else "unknown"
        ),
        "resource": (
            "resolved"
            if resources["resource_validation"]["resolved"] is True
            else "unresolved"
            if resources["resource_validation"]["resolved"] is False
            else "not_evaluated"
        ),
        "semantic": (
            "resolved"
            if semantics["fact_validation"]["resolved"] is True
            else "unresolved"
            if semantics["fact_validation"]["resolved"] is False
            else "not_evaluated"
        ),
    }
    return result


def validate_command(
    command: str,
    metadata_provider: MetadataProvider | None = None,
    resource_rule_provider: JsonResourceRuleProvider | None = None,
    semantic_rule_provider: JsonSemanticRuleProvider | None = None,
) -> dict[str, Any]:
    """Parse and analyze exactly one command without chain state."""
    return _analyze_parsed_command(
        parse_command(command),
        metadata_provider,
        resource_rule_provider,
        semantic_rule_provider,
    )


def _analyze_invocation(
    invocation: dict[str, Any],
    metadata_provider: MetadataProvider | None,
    resource_rule_provider: JsonResourceRuleProvider | None,
    semantic_rule_provider: JsonSemanticRuleProvider | None,
) -> dict[str, Any]:
    result = _analyze_parsed_command(
        invocation,
        metadata_provider,
        resource_rule_provider,
        semantic_rule_provider,
    )
    result["index"] = invocation["index"]
    result["operator_before"] = invocation["operator_before"]
    if invocation.get("nested_truncated"):
        result["nested_truncated"] = True
    if "nested_commands" in invocation:
        result["nested_commands"] = [
            _analyze_invocation(
                nested,
                metadata_provider,
                resource_rule_provider,
                semantic_rule_provider,
            )
            for nested in invocation["nested_commands"]
        ]
        result["nested_operators"] = invocation["nested_operators"]
    return result


def validate_shell(
    command: str,
    metadata_provider: MetadataProvider | None = None,
    resource_rule_provider: JsonResourceRuleProvider | None = None,
    semantic_rule_provider: JsonSemanticRuleProvider | None = None,
    *,
    max_depth: int = MAX_NESTED_SHELL_DEPTH,
) -> dict[str, Any]:
    """Extract and canonically analyze every supported shell invocation."""
    extracted = extract_command_invocations(command, max_depth=max_depth)
    commands = [
        _analyze_invocation(
            invocation,
            metadata_provider,
            resource_rule_provider,
            semantic_rule_provider,
        )
        for invocation in extracted["commands"]
    ]
    return {
        "raw_command": command,
        "commands": commands,
        "operators": extracted["operators"],
        "analysis": {
            "command_count": len(commands),
            "shell_structure": "structural_only",
            "max_depth": max_depth,
        },
    }


def _error(
    order: Any,
    command: str,
    stage: str,
    code: str,
    message: str,
    **details: Any,
) -> dict[str, Any]:
    return {
        "step": order,
        "stage": stage,
        "code": code,
        "command": command,
        **details,
        "message": message,
    }


def _diagnose_command(
    order: Any,
    command_result: dict[str, Any],
    *,
    invocation_path: tuple[int, ...] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    command = command_result["raw_command"]
    cli_validation = command_result["cli_validation"]
    resource_validation = command_result["resource_validation"]
    fact_validation = command_result["fact_validation"]
    errors: list[dict[str, Any]] = []
    status = "PASS"
    details: dict[str, Any] = {}
    if invocation_path is not None:
        details["invocation_path"] = list(invocation_path)

    if cli_validation["valid"] is not True:
        code = cli_validation["code"]
        status = "REJECT" if cli_validation["valid"] is False else "REVIEW"
        if "element" in cli_validation:
            details["element"] = cli_validation["element"]
        errors.append(
            _error(
                order,
                command,
                "cli_validation",
                code,
                "command arguments are invalid"
                if status == "REJECT"
                else "CLI metadata is unavailable or insufficient",
                **details,
            )
        )
    elif resource_validation["resolved"] is False:
        status = "REVIEW"
        errors.append(
            _error(
                order,
                command,
                "resource_mapping",
                "UNRESOLVED_RESOURCE",
                "resource semantics could not be resolved reliably",
                **details,
            )
        )
    elif fact_validation["resolved"] is False:
        status = "REVIEW"
        errors.append(
            _error(
                order,
                command,
                "semantic_mapping",
                "UNRESOLVED_SEMANTIC",
                "command semantics are valid but outside the current "
                "full-support subset",
                **details,
            )
        )
    return status, errors


def _flatten_commands(
    commands: list[dict[str, Any]],
    prefix: tuple[int, ...] = (),
):
    for command in commands:
        path = (*prefix, command["index"])
        yield path, command
        yield from _flatten_commands(command.get("nested_commands", []), path)


def _aggregate_resources(
    commands: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    available: set[str] = set()
    required: dict[str, dict[str, Any]] = {}
    produced: dict[str, dict[str, Any]] = {}
    for _path, command in _flatten_commands(commands):
        for resource in command["resources"]["requires"]:
            key = json.dumps(resource, sort_keys=True, separators=(",", ":"))
            if key not in available:
                required.setdefault(key, resource)
        for resource in command["resources"]["produces"]:
            key = json.dumps(resource, sort_keys=True, separators=(",", ":"))
            available.add(key)
            produced.setdefault(key, resource)
    return {
        "requires": list(required.values()),
        "produces": list(produced.values()),
    }


def _summary_validation(
    values: list[bool | None], unknown_code: str | None = None
) -> dict[str, Any]:
    if any(value is False for value in values):
        return {"valid": False, "code": None}
    if any(value is None for value in values):
        return {"valid": None, "code": unknown_code}
    return {"valid": True, "code": None}


def _summary_resolution(values: list[bool | None]) -> dict[str, Any]:
    if any(value is False for value in values):
        return {"resolved": False, "code": None}
    if any(value is None for value in values):
        return {"resolved": None, "code": None}
    return {"resolved": True, "code": None}


def _validate_step(
    step: dict[str, Any],
    metadata_provider: MetadataProvider | None,
    resource_rule_provider: JsonResourceRuleProvider | None,
    semantic_rule_provider: JsonSemanticRuleProvider | None,
) -> dict[str, Any]:
    order = step["order"]
    command = step["command"]
    try:
        shell_result = validate_shell(
            command,
            metadata_provider,
            resource_rule_provider,
            semantic_rule_provider,
        )
    except CommandParseError as exc:
        error = _error(
            order,
            command,
            "shell_parsing",
            "PARSER_ERROR",
            str(exc),
        )
        return {
            "order": order,
            "command": command,
            "status": "REVIEW",
            "resources": {"requires": [], "produces": []},
            "errors": [error],
        }

    commands = shell_result["commands"]
    flattened = list(_flatten_commands(commands))
    errors: list[dict[str, Any]] = []
    statuses = []
    for path, invocation in flattened:
        invocation_status, invocation_errors = _diagnose_command(
            order, invocation, invocation_path=path
        )
        invocation["status"] = invocation_status
        invocation["errors"] = invocation_errors
        statuses.append(invocation_status)
        errors.extend(invocation_errors)

    if "REJECT" in statuses:
        status = "REJECT"
    elif "REVIEW" in statuses:
        status = "REVIEW"
    else:
        status = "PASS"

    if len(commands) == 1 and "nested_commands" not in commands[0]:
        command_result = commands[0]
        return {
            "order": order,
            "command": command,
            "status": status,
            "executable": command_result["executable"],
            "argv": command_result["argv"],
            "support_tier": command_result["support_tier"],
            "elements": command_result["elements"],
            "cli_validation": command_result["cli_validation"],
            "resources": command_result["resources"],
            "resource_validation": command_result["resource_validation"],
            "facts": command_result["facts"],
            "fact_validation": command_result["fact_validation"],
            "analysis": command_result["analysis"],
            "commands": commands,
            "operators": shell_result["operators"],
            "errors": errors,
        }

    support_tiers = sorted(
        {invocation["support_tier"] for _path, invocation in flattened}
    )
    cli_values = [
        invocation["cli_validation"]["valid"]
        for _path, invocation in flattened
    ]
    resource_values = [
        invocation["resource_validation"]["resolved"]
        for _path, invocation in flattened
    ]
    fact_values = [
        invocation["fact_validation"]["resolved"]
        for _path, invocation in flattened
    ]
    resources = _aggregate_resources(commands)

    return {
        "order": order,
        "command": command,
        "status": status,
        "support_tier": support_tiers[0] if len(support_tiers) == 1 else "mixed",
        "commands": commands,
        "operators": shell_result["operators"],
        "cli_validation": _summary_validation(
            cli_values, "UNSUPPORTED_COMMAND"
        ),
        "resources": resources,
        "resource_validation": _summary_resolution(resource_values),
        "facts": [
            fact
            for _path, invocation in flattened
            for fact in invocation["facts"]
        ],
        "fact_validation": _summary_resolution(fact_values),
        "analysis": {
            **shell_result["analysis"],
            "support_tier": support_tiers[0]
            if len(support_tiers) == 1
            else "mixed",
            "support_tiers": support_tiers,
            "cli": "validated"
            if all(value is True for value in cli_values)
            else "unknown",
            "resource": "resolved"
            if all(value is True for value in resource_values)
            else "unknown",
            "semantic": "resolved"
            if all(value is True for value in fact_values)
            else "unknown",
        },
        "errors": errors,
    }


def validate_scenario(
    scenario: dict[str, Any],
    metadata_provider: MetadataProvider | None = None,
    resource_rule_provider: JsonResourceRuleProvider | None = None,
    semantic_rule_provider: JsonSemanticRuleProvider | None = None,
) -> dict[str, Any]:
    """Validate all scenario steps in order and aggregate Level 2 status."""
    ordered_steps = sorted(scenario["steps"], key=lambda step: step["order"])
    steps = [
        _validate_step(
            step,
            metadata_provider,
            resource_rule_provider,
            semantic_rule_provider,
        )
        for step in ordered_steps
    ]

    _dependency_errors, final_state = validate_dependencies(steps)
    errors = [error for step in steps for error in step["errors"]]

    statuses = {step["status"] for step in steps}
    if "REJECT" in statuses:
        status = "REJECT"
    elif "REVIEW" in statuses:
        status = "REVIEW"
    else:
        status = "PASS"

    return {
        "level": 2,
        "status": status,
        "steps": steps,
        "errors": errors,
        "resource_state": final_state,
    }
