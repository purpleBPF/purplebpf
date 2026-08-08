"""Public entry points for command and scenario Level 2 validation."""

from __future__ import annotations

from typing import Any

from .engine.chain_validator import validate_dependencies
from .engine.resource_mapper import JsonResourceRuleProvider, map_resources
from .parser.argument_mapper import map_arguments
from .parser.command_parser import CommandParseError, parse_command
from .parser.metadata_provider import MetadataProvider


def validate_command(
    command: str,
    metadata_provider: MetadataProvider | None = None,
    resource_rule_provider: JsonResourceRuleProvider | None = None,
) -> dict[str, Any]:
    """Parse, validate, and resource-map one command without chain state."""
    parsed = parse_command(command)
    result = map_arguments(parsed, metadata_provider)
    if result["cli_validation"]["valid"] is True:
        resources = map_resources(result, resource_rule_provider)
    else:
        resources = {
            "requires": [],
            "produces": [],
            "resource_validation": {"resolved": None, "code": None},
        }
    result["resources"] = {
        "requires": resources["requires"],
        "produces": resources["produces"],
    }
    result["resource_validation"] = resources["resource_validation"]
    return result


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


def _validate_step(
    step: dict[str, Any],
    metadata_provider: MetadataProvider | None,
    resource_rule_provider: JsonResourceRuleProvider | None,
) -> dict[str, Any]:
    order = step["order"]
    command = step["command"]
    try:
        command_result = validate_command(
            command, metadata_provider, resource_rule_provider
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

    cli_validation = command_result["cli_validation"]
    resource_validation = command_result["resource_validation"]
    errors: list[dict[str, Any]] = []
    status = "PASS"

    if cli_validation["valid"] is not True:
        code = cli_validation["code"]
        status = "REJECT" if cli_validation["valid"] is False else "REVIEW"
        details = {}
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
                else "command arguments could not be validated reliably",
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
            )
        )

    return {
        "order": order,
        "command": command,
        "status": status,
        "executable": command_result["executable"],
        "elements": command_result["elements"],
        "cli_validation": cli_validation,
        "resources": command_result["resources"],
        "resource_validation": resource_validation,
        "errors": errors,
    }


def validate_scenario(
    scenario: dict[str, Any],
    metadata_provider: MetadataProvider | None = None,
    resource_rule_provider: JsonResourceRuleProvider | None = None,
) -> dict[str, Any]:
    """Validate all scenario steps in order and aggregate Level 2 status."""
    ordered_steps = sorted(scenario["steps"], key=lambda step: step["order"])
    steps = [
        _validate_step(step, metadata_provider, resource_rule_provider)
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
