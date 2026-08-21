"""CLI entry point for the offline Level 2 accuracy evaluation."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from ..parser.command_parser import CommandParseError
from ..validator import validate_shell
from .comparator import (
    CLI_LABELS,
    ELEMENT_TYPES,
    TIERS,
    compare_case,
    empty_comparison,
)


EVALUATION_DIR = Path(__file__).parent
DEFAULT_DATASET = EVALUATION_DIR / "data" / "ground_truth.json"
DEFAULT_OUTPUT = EVALUATION_DIR / "results" / "latest.json"


def _merge(target: dict[str, Any], source: dict[str, Any]) -> None:
    for name in (
        "command_extraction",
        "command_order",
        "cli_validation",
        "argument_mapping",
        "resource",
        "fact",
        "tier",
    ):
        target[name].add(source[name])
    for kind in ELEMENT_TYPES:
        target["argument_by_type"][kind].add(source["argument_by_type"][kind])
    for name, value in source["cli_confusion"].items():
        target["cli_confusion"][name] += value
    for expected, actuals in source["cli_confusion_matrix"].items():
        for actual, value in actuals.items():
            target["cli_confusion_matrix"][expected][actual] += value
    for expected, actuals in source["tier_confusion"].items():
        for actual, value in actuals.items():
            target["tier_confusion"].setdefault(expected, {}).setdefault(actual, 0)
            target["tier_confusion"][expected][actual] += value
    target["failures"].extend(source["failures"])


def _finalize(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "command_extraction": {
            **raw["command_extraction"].result(),
            "order_accuracy": raw["command_order"].result()["accuracy"],
            "order_mismatches": (
                raw["command_order"].total - raw["command_order"].correct
            ),
        },
        "cli_validation": {
            **raw["cli_validation"].result(),
            **raw["cli_confusion"],
            "false_invalid": raw["cli_confusion"]["valid_to_invalid"],
            "false_valid": raw["cli_confusion"]["invalid_to_valid"],
            "confusion_matrix": raw["cli_confusion_matrix"],
        },
        "argument_mapping": {
            **raw["argument_mapping"].result(),
            "by_type": {
                kind: raw["argument_by_type"][kind].result()
                for kind in ELEMENT_TYPES
            },
        },
        "resource": raw["resource"].result(),
        "fact": raw["fact"].result(),
        "tier": {
            **raw["tier"].result(),
            "confusion_matrix": raw["tier_confusion"],
        },
        "failures": raw["failures"],
    }


def _load_dataset(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as dataset_file:
        dataset = json.load(dataset_file)
    cases = dataset.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("ground truth must contain a non-empty cases list")
    identifiers = [case.get("id") for case in cases]
    if any(not identifier for identifier in identifiers):
        raise ValueError("every ground-truth case must have an id")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("ground-truth case ids must be unique")
    return dataset


def evaluate_dataset(dataset_path: str | Path = DEFAULT_DATASET) -> dict[str, Any]:
    """Run static validation only and return machine-readable evaluation metrics."""
    path = Path(dataset_path)
    dataset = _load_dataset(path)
    aggregate = empty_comparison()
    per_subject_raw: dict[str, dict[str, Any]] = {}
    category_counts: Counter[str] = Counter()
    subject_counts: Counter[str] = Counter()

    for testcase in dataset["cases"]:
        category = testcase["category"]
        subject = testcase["subject"]
        category_counts[category] += 1
        subject_counts[subject] += 1
        try:
            actual = validate_shell(testcase["command"])
        except CommandParseError:
            actual = {"commands": []}
        comparison = compare_case(testcase, actual)
        _merge(aggregate, comparison)
        per_subject_raw.setdefault(subject, empty_comparison())
        _merge(per_subject_raw[subject], comparison)

    finalized = _finalize(aggregate)
    return {
        "schema_version": 1,
        "dataset": str(path),
        "total_cases": len(dataset["cases"]),
        "category_counts": dict(sorted(category_counts.items())),
        "subject_counts": dict(sorted(subject_counts.items())),
        **{key: value for key, value in finalized.items() if key != "failures"},
        "per_subject": {
            subject: {
                key: value
                for key, value in _finalize(raw).items()
                if key != "failures"
            }
            for subject, raw in sorted(per_subject_raw.items())
        },
        "failed_case_count": len(
            {failure["id"] for failure in finalized["failures"]}
        ),
        "failure_count": len(finalized["failures"]),
        "failures": finalized["failures"],
    }


def _percent(value: float) -> str:
    return f"{value:.4f}"


def render_report(result: dict[str, Any]) -> str:
    command = result["command_extraction"]
    cli = result["cli_validation"]
    arguments = result["argument_mapping"]
    resource = result["resource"]
    fact = result["fact"]
    tier = result["tier"]
    lines = [
        "Level 2 Evaluation",
        "==================",
        "",
        f"Total Cases: {result['total_cases']}",
        f"Failed Cases: {result['failed_case_count']}",
        "",
        "Command Extraction",
        f"Precision: {_percent(command['precision'])}",
        f"Recall: {_percent(command['recall'])}",
        f"F1: {_percent(command['f1'])}",
        f"Order Accuracy: {_percent(command['order_accuracy'])}",
        "",
        "CLI Validation",
        f"Accuracy: {_percent(cli['accuracy'])}",
        f"Valid -> Invalid: {cli['valid_to_invalid']}",
        f"Invalid -> Valid: {cli['invalid_to_valid']}",
        "Confusion Matrix (Expected x Actual)",
        "Expected      VALID  INVALID  UNKNOWN",
    ]
    for expected in CLI_LABELS:
        row = cli["confusion_matrix"].get(expected, {})
        lines.append(
            f"{expected:<12} {row.get('VALID', 0):>5}  "
            f"{row.get('INVALID', 0):>7}  {row.get('UNKNOWN', 0):>7}"
        )
    lines.extend(
        [
            "",
            "Argument Mapping",
            f"Precision: {_percent(arguments['precision'])}",
            f"Recall: {_percent(arguments['recall'])}",
            f"F1: {_percent(arguments['f1'])}",
        ]
    )
    for kind in ELEMENT_TYPES:
        metrics = arguments["by_type"][kind]
        lines.append(
            f"{kind}: P={_percent(metrics['precision'])} "
            f"R={_percent(metrics['recall'])} F1={_percent(metrics['f1'])}"
        )
    lines.extend(
        [
            "",
            "Resource",
            f"Precision: {_percent(resource['precision'])}",
            f"Recall: {_percent(resource['recall'])}",
            f"F1: {_percent(resource['f1'])}",
            "",
            "Fact",
            f"Precision: {_percent(fact['precision'])}",
            f"Recall: {_percent(fact['recall'])}",
            f"F1: {_percent(fact['f1'])}",
            "",
            "Tier Classification",
            f"Accuracy: {_percent(tier['accuracy'])}",
            "Confusion Matrix (Expected x Actual)",
            "Expected      FULL  METADATA  GENERIC  MISSING",
        ]
    )
    for expected in TIERS:
        row = tier["confusion_matrix"].get(expected, {})
        lines.append(
            f"{expected:<12} {row.get('FULL', 0):>4}  "
            f"{row.get('METADATA', 0):>8}  {row.get('GENERIC', 0):>7}  "
            f"{row.get('MISSING', 0):>7}"
        )
    lines.extend(
        [
            "",
            f"Mismatch Records: {result['failure_count']}",
            "See the JSON result for complete failed-case details.",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--no-write", action="store_true", help="do not write a JSON result"
    )
    args = parser.parse_args(argv)

    result = evaluate_dataset(args.dataset)
    print(render_report(result))
    if not args.no_write:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"\nJSON Result: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
