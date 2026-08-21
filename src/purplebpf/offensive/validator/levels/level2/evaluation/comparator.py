"""Compare human-authored Level 2 ground truth with Validator output."""

from __future__ import annotations

import json
from collections import Counter
from itertools import zip_longest
from typing import Any, Iterable

from .metrics import AccuracyCounts, PRFCounts


ELEMENT_TYPES = ("option", "option_value", "operand")
TIERS = ("FULL", "METADATA", "GENERIC")
CLI_LABELS = ("VALID", "INVALID", "UNKNOWN")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _counter(values: Iterable[Any]) -> Counter[str]:
    return Counter(_canonical(value) for value in values)


def _compare_collections(expected: Iterable[Any], actual: Iterable[Any]) -> tuple[
    PRFCounts, list[str], list[str]
]:
    expected_counter = _counter(expected)
    actual_counter = _counter(actual)
    common = expected_counter & actual_counter
    missing = expected_counter - actual_counter
    unexpected = actual_counter - expected_counter
    counts = PRFCounts(
        tp=sum(common.values()),
        fp=sum(unexpected.values()),
        fn=sum(missing.values()),
    )
    return counts, list(missing.elements()), list(unexpected.elements())


def flatten_actual_commands(commands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten wrapper and nested shell invocations in canonical traversal order."""
    flattened: list[dict[str, Any]] = []
    for command in commands:
        flattened.append(command)
        flattened.extend(flatten_actual_commands(command.get("nested_commands", [])))
    return flattened


def _actual_resources(command: dict[str, Any]) -> list[dict[str, Any]]:
    flattened = []
    for role in ("requires", "produces"):
        for resource in command.get("resources", {}).get(role, []):
            flattened.append({"role": role, **resource})
    return flattened


def _expected_resources(command: dict[str, Any]) -> list[dict[str, Any]]:
    resources = command.get("resources", {})
    flattened = []
    for role in ("requires", "produces"):
        for resource in resources.get(role, []):
            flattened.append({"role": role, **resource})
    return flattened


def empty_comparison() -> dict[str, Any]:
    return {
        "command_extraction": PRFCounts(),
        "command_order": AccuracyCounts(),
        "cli_validation": AccuracyCounts(),
        "cli_confusion": {
            "valid_to_invalid": 0,
            "invalid_to_valid": 0,
            "expected_valid_actual_unknown": 0,
            "expected_invalid_actual_unknown": 0,
        },
        "cli_confusion_matrix": {
            expected: {actual: 0 for actual in CLI_LABELS}
            for expected in CLI_LABELS
        },
        "argument_mapping": PRFCounts(),
        "argument_by_type": {kind: PRFCounts() for kind in ELEMENT_TYPES},
        "resource": PRFCounts(),
        "fact": PRFCounts(),
        "tier": AccuracyCounts(),
        "tier_confusion": {
            expected: {actual: 0 for actual in (*TIERS, "MISSING")}
            for expected in TIERS
        },
        "failures": [],
    }


def _failure(
    case_id: str,
    metric: str,
    *,
    expected: Any | None = None,
    actual: Any | None = None,
    missing: list[str] | None = None,
    unexpected: list[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"id": case_id, "metric": metric}
    if expected is not None:
        result["expected"] = expected
    if actual is not None:
        result["actual"] = actual
    if missing:
        result["missing"] = [json.loads(item) for item in missing]
    if unexpected:
        result["unexpected"] = [json.loads(item) for item in unexpected]
    return result


def compare_case(
    testcase: dict[str, Any], validator_output: dict[str, Any]
) -> dict[str, Any]:
    """Return raw metric counts and human-readable mismatches for one case."""
    comparison = empty_comparison()
    case_id = testcase["id"]
    expected_commands = testcase["expected"]["commands"]
    actual_commands = flatten_actual_commands(validator_output["commands"])
    expected_names = [command["executable"] for command in expected_commands]
    actual_names = [command["executable"]["raw"] for command in actual_commands]

    counts, missing, unexpected = _compare_collections(expected_names, actual_names)
    comparison["command_extraction"] = counts
    order_matches = expected_names == actual_names
    comparison["command_order"] = AccuracyCounts(int(order_matches), 1)
    if missing or unexpected:
        comparison["failures"].append(
            _failure(
                case_id,
                "command_extraction",
                missing=missing,
                unexpected=unexpected,
            )
        )
    elif not order_matches:
        comparison["failures"].append(
            _failure(
                case_id,
                "command_order",
                expected=expected_names,
                actual=actual_names,
            )
        )

    for expected, actual in zip_longest(expected_commands, actual_commands):
        if expected is None:
            continue
        executable = expected["executable"]
        actual_matches = (
            actual is not None and actual["executable"]["raw"] == executable
        )

        expected_tier = expected.get("tier")
        if expected_tier is not None:
            actual_tier = (
                str(actual.get("support_tier", "MISSING")).upper()
                if actual_matches
                else "MISSING"
            )
            comparison["tier"].total += 1
            comparison["tier"].correct += int(expected_tier == actual_tier)
            comparison["tier_confusion"].setdefault(expected_tier, {}).setdefault(
                actual_tier, 0
            )
            comparison["tier_confusion"][expected_tier][actual_tier] += 1
            if expected_tier != actual_tier:
                comparison["failures"].append(
                    _failure(
                        case_id,
                        "tier",
                        expected={"executable": executable, "tier": expected_tier},
                        actual={"executable": executable, "tier": actual_tier},
                    )
                )

        if "cli_valid" in expected:
            expected_valid = expected["cli_valid"]
            actual_valid = (
                actual.get("cli_validation", {}).get("valid")
                if actual_matches
                else None
            )
            expected_cli_label = (
                "VALID"
                if expected_valid is True
                else "INVALID"
                if expected_valid is False
                else "UNKNOWN"
            )
            actual_cli_label = (
                "VALID"
                if actual_valid is True
                else "INVALID"
                if actual_valid is False
                else "UNKNOWN"
            )
            comparison["cli_confusion_matrix"][expected_cli_label][
                actual_cli_label
            ] += 1
            comparison["cli_validation"].total += 1
            comparison["cli_validation"].correct += int(
                expected_valid is actual_valid
            )
            if expected_valid is not actual_valid:
                if expected_valid is True and actual_valid is False:
                    comparison["cli_confusion"]["valid_to_invalid"] += 1
                elif expected_valid is False and actual_valid is True:
                    comparison["cli_confusion"]["invalid_to_valid"] += 1
                elif expected_valid is True:
                    comparison["cli_confusion"][
                        "expected_valid_actual_unknown"
                    ] += 1
                else:
                    comparison["cli_confusion"][
                        "expected_invalid_actual_unknown"
                    ] += 1
                comparison["failures"].append(
                    _failure(
                        case_id,
                        "cli_validation",
                        expected={"executable": executable, "valid": expected_valid},
                        actual={"executable": executable, "valid": actual_valid},
                    )
                )
            expected_error = expected.get("error_code")
            if expected_error is not None:
                actual_error = (
                    actual.get("cli_validation", {}).get("code")
                    if actual_matches
                    else None
                )
                if expected_error != actual_error:
                    comparison["failures"].append(
                        _failure(
                            case_id,
                            "cli_error_code",
                            expected=expected_error,
                            actual=actual_error,
                        )
                    )

        if "elements" in expected:
            actual_elements = actual.get("elements", []) if actual_matches else []
            element_counts, missing, unexpected = _compare_collections(
                expected["elements"], actual_elements
            )
            comparison["argument_mapping"].add(element_counts)
            for kind in ELEMENT_TYPES:
                kind_counts, _, _ = _compare_collections(
                    [item for item in expected["elements"] if item["type"] == kind],
                    [item for item in actual_elements if item["type"] == kind],
                )
                comparison["argument_by_type"][kind].add(kind_counts)
            if missing or unexpected:
                comparison["failures"].append(
                    _failure(
                        case_id,
                        "argument_mapping",
                        missing=missing,
                        unexpected=unexpected,
                    )
                )

        if "resources" in expected:
            actual_resources = _actual_resources(actual) if actual_matches else []
            resource_counts, missing, unexpected = _compare_collections(
                _expected_resources(expected), actual_resources
            )
            comparison["resource"].add(resource_counts)
            if missing or unexpected:
                comparison["failures"].append(
                    _failure(
                        case_id,
                        "resource",
                        missing=missing,
                        unexpected=unexpected,
                    )
                )

        if "facts" in expected:
            actual_facts = actual.get("facts", []) if actual_matches else []
            fact_counts, missing, unexpected = _compare_collections(
                expected["facts"], actual_facts
            )
            comparison["fact"].add(fact_counts)
            if missing or unexpected:
                comparison["failures"].append(
                    _failure(
                        case_id,
                        "fact",
                        missing=missing,
                        unexpected=unexpected,
                    )
                )

    return comparison
