"""Map validated command elements to chain resources using declarative rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .resource import Resource


class JsonResourceRuleProvider:
    """Load resource semantics independently from parser and CLI metadata."""

    def __init__(self, path: str | Path | None = None):
        default_path = Path(__file__).parents[1] / "rules" / "resource_rules.json"
        self._path = Path(path) if path is not None else default_path
        self._rules: dict[str, dict[str, Any]] | None = None

    def get(self, executable: str) -> dict[str, Any] | None:
        if self._rules is None:
            with self._path.open(encoding="utf-8") as rule_file:
                self._rules = json.load(rule_file)["commands"]
        return self._rules.get(executable)


def _options(elements: list[dict[str, Any]]) -> set[str]:
    return {
        element["raw"] for element in elements if element.get("type") == "option"
    }


def _option_values(elements: list[dict[str, Any]]) -> dict[str, str]:
    return {
        element["option"]: element["raw"]
        for element in elements
        if element.get("type") == "option_value"
    }


def _condition_matches(effect: dict[str, Any], present_options: set[str]) -> bool:
    condition = effect.get("when", {})
    option_any = set(condition.get("option_any", []))
    option_none = set(condition.get("option_none", []))
    return (not option_any or bool(option_any & present_options)) and not (
        option_none & present_options
    )


def _source_value(
    source: dict[str, Any],
    operands: dict[int, str],
    option_values: dict[str, str],
    current_operand: str | None,
) -> str | None:
    if "first_available" in source:
        for candidate in source["first_available"]:
            value = _source_value(
                candidate, operands, option_values, current_operand
            )
            if value is not None:
                return value
        return None
    if "const" in source:
        return source["const"]
    if source.get("operand") == "current":
        return current_operand
    if "option_value_any" in source:
        return next(
            (
                option_values[option]
                for option in source["option_value_any"]
                if option in option_values
            ),
            None,
        )
    return operands.get(source["operand"])


def _identity(
    specification: dict[str, Any],
    operands: dict[int, str],
    option_values: dict[str, str],
    current_operand: str | None,
) -> dict[str, str] | None:
    identity: dict[str, str] = {}
    for name, source in specification.items():
        value = _source_value(source, operands, option_values, current_operand)
        if value is None:
            return None
        identity[name] = value
    return identity


def _resolve_effects(
    effects: list[dict[str, Any]], elements: list[dict[str, Any]]
) -> tuple[list[Resource], bool]:
    operands = {
        element["position"]: element["raw"]
        for element in elements
        if element.get("type") == "operand"
    }
    present_options = _options(elements)
    option_values = _option_values(elements)
    resources: list[Resource] = []
    unresolved = False

    for effect in effects:
        if not _condition_matches(effect, present_options):
            continue

        iterator = effect.get("for_each_operand")
        if iterator is not None:
            selected = [
                value
                for position, value in sorted(operands.items())
                if position >= iterator.get("start", 1)
            ]
            if not selected:
                unresolved = True
            for operand in selected:
                identity = _identity(
                    effect["identity"], operands, option_values, operand
                )
                if identity is None:
                    unresolved = True
                else:
                    resources.append(Resource.create(effect["type"], identity))
            continue

        identity = _identity(effect["identity"], operands, option_values, None)
        if identity is None:
            unresolved = True
        else:
            resources.append(Resource.create(effect["type"], identity))

    return resources, unresolved


def map_resources(
    command_result: dict[str, Any],
    rule_provider: JsonResourceRuleProvider | None = None,
) -> dict[str, Any]:
    """Return requires/produces plus resource resolution status."""
    provider = rule_provider or JsonResourceRuleProvider()
    executable = command_result["executable"]["normalized"]
    rule = provider.get(executable)

    empty = {"requires": [], "produces": []}
    if rule is None:
        return {
            **empty,
            "resource_validation": {"resolved": True, "code": None},
        }

    requires, requires_unresolved = _resolve_effects(
        rule.get("requires", []), command_result["elements"]
    )
    produces, produces_unresolved = _resolve_effects(
        rule.get("produces", []), command_result["elements"]
    )
    unresolved = requires_unresolved or produces_unresolved

    if rule.get("resolution") == "required" and not requires and not produces:
        unresolved = True

    return {
        "requires": [resource.to_dict() for resource in requires],
        "produces": [resource.to_dict() for resource in produces],
        "resource_validation": {
            "resolved": not unresolved,
            "code": "UNRESOLVED_RESOURCE" if unresolved else None,
        },
    }
