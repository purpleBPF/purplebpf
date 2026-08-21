"""Run all benign scenarios through the validator pipeline."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
DEFAULT_SCENARIO_DIR = REPOSITORY_ROOT / "demo" / "benign"
DEFAULT_OUTPUT = Path(__file__).parent / "results" / "benign_latest.json"

Validator = Callable[[dict[str, Any]], dict[str, Any]]


def load_dataset(
    scenario_dir: str | Path = DEFAULT_SCENARIO_DIR,
) -> list[dict[str, Any]]:
    """Load all benign scenario JSON files in filename order."""
    directory = Path(scenario_dir)
    dataset: list[dict[str, Any]] = []

    for path in sorted(directory.glob("*.json")):
        with path.open(encoding="utf-8") as scenario_file:
            scenario = json.load(scenario_file)

        if not isinstance(scenario, dict):
            raise ValueError(f"{path} must contain a JSON object")

        dataset.append(
            {
                "file": path.name,
                "scenario": scenario,
            }
        )

    return dataset


def _default_validator(scenario: dict[str, Any]) -> dict[str, Any]:
    from purplebpf.offensive.validator.main import validate_scenario_pipeline

    return validate_scenario_pipeline(scenario)


def _status(level: Any) -> str | None:
    return level.get("status") if isinstance(level, dict) else None


def _diagnostic_code(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, int):
        return f"SC{value}"

    text = str(value)
    return text if text.startswith("SC") else text


def _collect_errors(
    result: dict[str, Any],
) -> tuple[list[str], list[str]]:
    codes: list[str] = []
    messages: list[str] = []

    def add(code: Any, message: Any) -> None:
        normalized = _diagnostic_code(code)

        if normalized and normalized not in codes:
            codes.append(normalized)

        if message is not None:
            text = str(message)
            if text and text not in messages:
                messages.append(text)

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for error in value.get("errors", []):
                if isinstance(error, dict):
                    add(
                        error.get("code"),
                        error.get("message"),
                    )

            for diagnostic in value.get("diagnostic_items", []):
                if isinstance(diagnostic, dict):
                    add(
                        diagnostic.get("code"),
                        diagnostic.get("message"),
                    )

            for key, child in value.items():
                if key not in {"errors", "diagnostic_items"}:
                    walk(child)

        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(result)
    return codes, messages


def classify_result(
    result: dict[str, Any],
    error_codes: Sequence[str],
) -> str:
    """Assign an analysis category without changing the validator status."""
    final = result.get("final", {})
    final_status = final.get("status")

    if final_status == "PASS":
        return "pass"

    if final_status == "REVIEW":
        return "review"

    if final_status == "ERROR":
        return "error"

    if final_status != "REJECT":
        return "other_reject"

    if (
        _status(result.get("level3")) == "REJECT"
        and "TECHNIQUE_ACTION_MISMATCH" in error_codes
    ):
        return "semantic_reject"

    if (
        final.get("stopped_at") == "level1"
        or _status(result.get("level1")) == "FAIL"
    ):
        return "level1_reject"

    if (
        final.get("stopped_at") == "level2"
        or _status(result.get("level2")) in {"FAIL", "REJECT"}
    ):
        return "level2_coverage_reject"

    return "other_reject"


def _ratio(
    numerator: int,
    denominator: int,
) -> float:
    return numerator / denominator if denominator else 0.0


def _build_status_summary(
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build PASS/REVIEW/REJECT/ERROR counts and rates for a case list."""
    counts = Counter(case["final_status"] for case in cases)
    total = len(cases)

    return {
        "total": total,
        "pass": counts["PASS"],
        "review": counts["REVIEW"],
        "reject": counts["REJECT"],
        "error": counts["ERROR"],
        "pass_rate": _ratio(counts["PASS"], total),
        "review_rate": _ratio(counts["REVIEW"], total),
        "reject_rate": _ratio(counts["REJECT"], total),
        "error_rate": _ratio(counts["ERROR"], total),
    }


def evaluate_dataset(
    scenario_dir: str | Path = DEFAULT_SCENARIO_DIR,
    *,
    validator: Validator | None = None,
) -> dict[str, Any]:
    """Validate all benign scenarios and return aggregate and per-case results."""
    validate = validator or _default_validator
    cases: list[dict[str, Any]] = []

    for item in load_dataset(scenario_dir):
        scenario = item["scenario"]

        try:
            validation = validate(scenario)

            error_codes, error_messages = _collect_errors(validation)
            final = validation.get("final", {})

            case = {
                "file": item["file"],
                "label": scenario.get("label"),
                "kind": scenario.get("kind"),
                "technique_id": scenario.get("technique_id"),
                "level1_status": _status(validation.get("level1")),
                "level2_status": _status(validation.get("level2")),
                "level3_status": _status(validation.get("level3")),
                "final_status": final.get("status"),
                "stopped_at": final.get("stopped_at"),
                "final_reason": final.get("reason"),
                "error_codes": error_codes,
                "error_messages": error_messages,
            }

            case["category"] = classify_result(
                validation,
                error_codes,
            )

        except Exception as exc:
            case = {
                "file": item["file"],
                "label": scenario.get("label"),
                "kind": scenario.get("kind"),
                "technique_id": scenario.get("technique_id"),
                "level1_status": None,
                "level2_status": None,
                "level3_status": None,
                "final_status": "ERROR",
                "stopped_at": None,
                "final_reason": "EVALUATION_EXCEPTION",
                "error_codes": [type(exc).__name__],
                "error_messages": [str(exc)],
                "category": "error",
            }

        cases.append(case)

    # -----------------------------
    # 전체 summary
    # -----------------------------
    status_counts = Counter(
        case["final_status"]
        for case in cases
    )

    category_counts = Counter(
        case["category"]
        for case in cases
    )

    total = len(cases)
    benign_pass_count = status_counts["PASS"]

    summary = {
        "total": total,
        "pass": status_counts["PASS"],
        "review": status_counts["REVIEW"],
        "reject": status_counts["REJECT"],
        "error": status_counts["ERROR"],

        "semantic_reject": category_counts["semantic_reject"],
        "level2_coverage_reject": category_counts[
            "level2_coverage_reject"
        ],
        "level1_reject": category_counts["level1_reject"],
        "other_reject": category_counts["other_reject"],

        "benign_pass_count": benign_pass_count,

        "pass_rate": _ratio(
            status_counts["PASS"],
            total,
        ),
        "review_rate": _ratio(
            status_counts["REVIEW"],
            total,
        ),
        "reject_rate": _ratio(
            status_counts["REJECT"],
            total,
        ),
        "error_rate": _ratio(
            status_counts["ERROR"],
            total,
        ),

        "semantic_reject_rate": _ratio(
            category_counts["semantic_reject"],
            total,
        ),
        "coverage_reject_rate": _ratio(
            category_counts["level2_coverage_reject"],
            total,
        ),

        "benign_pass_rate": _ratio(
            benign_pass_count,
            total,
        ),
        "false_positive_candidate_rate": _ratio(
            benign_pass_count,
            total,
        ),
    }

    # -----------------------------
    # kind별 summary
    # normal / trap / unknown
    # -----------------------------
    cases_by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for case in cases:
        kind = case["kind"] or "unknown"
        cases_by_kind[kind].append(case)

    kind_summary = {
        kind: _build_status_summary(kind_cases)
        for kind, kind_cases in sorted(cases_by_kind.items())
    }

    # -----------------------------
    # Technique별 summary
    # -----------------------------
    technique_counts: dict[str, Counter[str]] = defaultdict(Counter)

    for case in cases:
        technique = case["technique_id"] or "UNKNOWN"

        technique_counts[technique]["total"] += 1
        technique_counts[technique][
            str(case["final_status"]).lower()
        ] += 1

    technique_summary = {
        technique: {
            "total": counts["total"],
            "pass": counts["pass"],
            "review": counts["review"],
            "reject": counts["reject"],
            "error": counts["error"],

            "pass_rate": _ratio(
                counts["pass"],
                counts["total"],
            ),
            "review_rate": _ratio(
                counts["review"],
                counts["total"],
            ),
            "reject_rate": _ratio(
                counts["reject"],
                counts["total"],
            ),
            "error_rate": _ratio(
                counts["error"],
                counts["total"],
            ),
        }
        for technique, counts in sorted(
            technique_counts.items()
        )
    }

    return {
        "summary": summary,
        "kind_summary": kind_summary,
        "technique_summary": technique_summary,
        "cases": cases,
    }


def main(
    argv: Sequence[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
    )

    parser.add_argument(
        "--scenario-dir",
        type=Path,
        default=DEFAULT_SCENARIO_DIR,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    parser.add_argument(
        "--no-write",
        action="store_true",
    )

    args = parser.parse_args(argv)

    result = evaluate_dataset(
        args.scenario_dir
    )

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )

    if not args.no_write:
        args.output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        args.output.write_text(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())