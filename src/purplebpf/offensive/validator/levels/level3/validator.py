"""Public Level 3 scenario validator."""

from __future__ import annotations

from typing import Any

from ..level2.parser.command_parser import CommandParseError
from ..level2.validator import validate_shell as validate_level2_shell

from .engine.technique_action_validator import validate_technique_actions
from .engine.technique_rule_provider import JsonTechniqueRuleProvider
from .mapper.action_mapper import UNMAPPED_ACTION, map_actions
from .mapper.action_rule_provider import JsonActionRuleProvider
from .providers.attack_provider import AttackProvider


def _error(code: str, stage: str, message: str) -> dict[str, str]:
    return {"stage": stage, "code": code, "message": message}


def _level2_by_order(level2_output: dict[str, Any] | None) -> dict[Any, dict[str, Any]]:
    if level2_output is None:
        return {}
    return {step["order"]: step for step in level2_output.get("steps", [])}


def _map_step(
    step: dict[str, Any],
    existing_level2: dict[Any, dict[str, Any]],
    action_rule_provider: JsonActionRuleProvider | None,
) -> dict[str, Any]:
    order = step["order"]
    command = step["command"]
    try:
        level2_result = existing_level2.get(order)
        if level2_result is None:
            shell_result = validate_level2_shell(command)
            if (
                len(shell_result["commands"]) == 1
                and "nested_commands" not in shell_result["commands"][0]
            ):
                level2_result = shell_result["commands"][0]
            else:
                level2_result = shell_result

        def flatten(results: list[dict[str, Any]]):
            for result in results:
                yield result
                yield from flatten(result.get("nested_commands", []))

        invocation_results = (
            list(flatten(level2_result["commands"]))
            if "commands" in level2_result
            else [level2_result]
        )
        actions = []
        for invocation_result in invocation_results:
            mapped = map_actions(invocation_result, action_rule_provider)
            actions.extend(mapped["actions"])
        action_result = {
            "actions": actions,
            "action_validation": {
                "mapped": bool(actions),
                "code": None if actions else UNMAPPED_ACTION,
            },
        }
    except CommandParseError as exc:
        level2_result = None
        action_result = {
            "raw_command": command,
            "executable": None,
            "actions": [],
            "action_validation": {
                "mapped": False,
                "code": UNMAPPED_ACTION,
                "source_code": "PARSER_ERROR",
                "message": str(exc),
            },
        }

    return {
        "order": order,
        "command": command,
        "level2": level2_result,
        "actions": action_result["actions"],
        "action_validation": action_result["action_validation"],
    }


def validate_scenario(
    scenario: dict[str, Any],
    level2_output: dict[str, Any] | None = None,
    attack_provider: AttackProvider | None = None,
    action_rule_provider: JsonActionRuleProvider | None = None,
    technique_rule_provider: JsonTechniqueRuleProvider | None = None,
) -> dict[str, Any]:
    """Lookup, independently map Actions, and validate one scenario Technique."""
    technique_id = scenario.get("technique_id", "")
    provider = attack_provider or AttackProvider()
    technique_lookup = provider.get_technique(technique_id)

    if not technique_lookup["found"]:
        error = _error(
            technique_lookup["code"],
            "technique_lookup",
            "Technique ID was not found in the local Enterprise ATT&CK data",
        )
        return {
            "level": 3,
            "status": "REVIEW",
            "technique_lookup": technique_lookup,
            "steps": [],
            "technique_validation": None,
            "errors": [error],
        }

    existing_level2 = _level2_by_order(level2_output)
    steps = [
        _map_step(step, existing_level2, action_rule_provider)
        for step in sorted(scenario.get("steps", []), key=lambda item: item["order"])
    ]
    technique_validation = validate_technique_actions(
        technique_lookup["technique"]["id"], steps, technique_rule_provider
    )

    matched = technique_validation["matched"]
    if matched is True:
        status = "PASS"
        errors: list[dict[str, str]] = []
    elif matched is False:
        status = "REJECT"
        errors = [
            _error(
                technique_validation["code"],
                "technique_action_validation",
                "Scenario Actions do not satisfy a supported Technique core pattern",
            )
        ]
    else:
        status = "REVIEW"
        errors = [
            _error(
                technique_validation["code"],
                "technique_action_validation",
                "Technique semantics could not be determined with current rules and evidence",
            )
        ]

    return {
        "level": 3,
        "status": status,
        "technique_lookup": technique_lookup,
        "steps": steps,
        "technique_validation": technique_validation,
        "errors": errors,
    }
