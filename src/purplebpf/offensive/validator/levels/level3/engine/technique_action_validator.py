"""Match scenario Actions against declarative ATT&CK Technique patterns."""

from __future__ import annotations

from typing import Any

from .technique_rule_provider import JsonTechniqueRuleProvider


UNSUPPORTED_TECHNIQUE_RULE = "UNSUPPORTED_TECHNIQUE_RULE"
TECHNIQUE_ACTION_MISMATCH = "TECHNIQUE_ACTION_MISMATCH"
INSUFFICIENT_ACTION_CONTEXT = "INSUFFICIENT_ACTION_CONTEXT"
UNMAPPED_ACTION = "UNMAPPED_ACTION"


def _flatten_actions(step_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for step in step_results:
        for action in step.get("actions", []):
            flattened.append(
                {
                    "step_order": step.get("order"),
                    "command": step.get("command"),
                    **action,
                }
            )
    return flattened


def _context_status(
    required: dict[str, Any], actual: dict[str, Any]
) -> str:
    missing = False
    for key, value in required.items():
        if key not in actual:
            missing = True
        elif actual[key] != value:
            return "conflict"
    return "missing" if missing else "match"


def _match_pattern(
    pattern: dict[str, Any], actions: list[dict[str, Any]]
) -> dict[str, Any]:
    requirements = pattern["required"]

    def assign(
        requirement_index: int,
        used: set[int],
        allowed_statuses: set[str],
    ) -> list[int] | None:
        if requirement_index == len(requirements):
            return []
        requirement = requirements[requirement_index]
        for action_index, action in enumerate(actions):
            if action_index in used or action.get("action") != requirement["action"]:
                continue
            status = _context_status(
                requirement.get("context", {}), action.get("context", {})
            )
            if status not in allowed_statuses:
                continue
            remainder = assign(
                requirement_index + 1, used | {action_index}, allowed_statuses
            )
            if remainder is not None:
                return [action_index, *remainder]
        return None

    exact_assignment = assign(0, set(), {"match"})
    if exact_assignment is not None:
        evidence = [
            {
                "step_order": actions[index]["step_order"],
                "command": actions[index]["command"],
                "action": actions[index]["action"],
                "context": actions[index].get("context", {}),
                "evidence": actions[index].get("evidence", {}),
            }
            for index in exact_assignment
        ]
        return {"matched": True, "indeterminate": False, "evidence": evidence}

    possible_assignment = assign(0, set(), {"match", "missing"})
    return {
        "matched": False,
        "indeterminate": possible_assignment is not None,
        "evidence": [],
    }


def _supporting_evidence(
    rule: dict[str, Any], actions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for supporting in rule.get("supporting_actions", []):
        for action in actions:
            if action.get("action") != supporting["action"]:
                continue
            if _context_status(
                supporting.get("context", {}), action.get("context", {})
            ) != "match":
                continue
            evidence.append(
                {
                    "step_order": action["step_order"],
                    "command": action["command"],
                    "action": action["action"],
                    "context": action.get("context", {}),
                }
            )
    return evidence


def validate_technique_actions(
    technique_id: str,
    step_results: list[dict[str, Any]],
    rule_provider: JsonTechniqueRuleProvider | None = None,
) -> dict[str, Any]:
    """Match OR patterns containing AND-required Actions with context subsets."""
    provider = rule_provider or JsonTechniqueRuleProvider()
    rule = provider.get(technique_id)
    if rule is None:
        return {
            "technique_id": technique_id,
            "matched": None,
            "matched_pattern": None,
            "required_actions": [],
            "evidence": [],
            "supporting_evidence": [],
            "code": UNSUPPORTED_TECHNIQUE_RULE,
        }

    actions = _flatten_actions(step_results)
    indeterminate = False
    for index, pattern in enumerate(rule["patterns"]):
        result = _match_pattern(pattern, actions)
        if result["matched"]:
            return {
                "technique_id": technique_id,
                "matched": True,
                "matched_pattern": index,
                "matched_pattern_id": pattern.get("id"),
                "required_actions": pattern["required"],
                "evidence": result["evidence"],
                "supporting_evidence": _supporting_evidence(rule, actions),
                "code": None,
            }
        indeterminate = indeterminate or result["indeterminate"]

    has_unmapped = any(
        step.get("action_validation", {}).get("code") == UNMAPPED_ACTION
        for step in step_results
    )
    if indeterminate:
        code = INSUFFICIENT_ACTION_CONTEXT
        matched: bool | None = None
    elif has_unmapped:
        code = UNMAPPED_ACTION
        matched = None
    else:
        code = TECHNIQUE_ACTION_MISMATCH
        matched = False

    return {
        "technique_id": technique_id,
        "matched": matched,
        "matched_pattern": None,
        "required_actions": [],
        "evidence": [],
        "supporting_evidence": _supporting_evidence(rule, actions),
        "code": code,
    }
