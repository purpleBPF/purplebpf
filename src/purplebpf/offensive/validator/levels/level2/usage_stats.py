"""Development-only command usage aggregation for scenario JSON data."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .engine.semantic_mapper import JsonSemanticRuleProvider
from .parser.command_parser import extract_command_invocations
from .parser.metadata_provider import JsonMetadataProvider, MetadataProvider
from .support_tier import resolve_support_tier


_SYSTEM_EXECUTABLE_DIRECTORIES = {
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
}


def _flatten(commands: list[dict[str, Any]]):
    for command in commands:
        yield command
        yield from _flatten(command.get("nested_commands", []))


def _statistics_key(executable: dict[str, str]) -> str:
    raw = executable["raw"]
    path = Path(raw)
    if "/" not in raw or str(path.parent) in _SYSTEM_EXECUTABLE_DIRECTORIES:
        return executable["normalized"]
    return raw


def _tier(
    executable: dict[str, str],
    metadata_provider: MetadataProvider,
    semantic_rule_provider: JsonSemanticRuleProvider,
) -> str:
    return resolve_support_tier(
        executable["normalized"], metadata_provider, semantic_rule_provider
    )


def collect_command_usage(
    scenarios: Iterable[dict[str, Any]],
    metadata_provider: MetadataProvider | None = None,
    semantic_rule_provider: JsonSemanticRuleProvider | None = None,
) -> list[dict[str, Any]]:
    """Aggregate normalized executable usage without affecting validation."""
    provider = metadata_provider or JsonMetadataProvider()
    semantics = semantic_rule_provider or JsonSemanticRuleProvider()
    records: dict[str, dict[str, Any]] = {}

    for scenario_index, scenario in enumerate(scenarios):
        technique_id = scenario.get("technique_id")
        scenario_seen: set[str] = set()
        for step in scenario.get("steps", []):
            step_seen: set[str] = set()
            extracted = extract_command_invocations(step["command"])
            for invocation in _flatten(extracted["commands"]):
                key = _statistics_key(invocation["executable"])
                record = records.setdefault(
                    key,
                    {
                        "command": key,
                        "techniques": set(),
                        "scenario_ids": set(),
                        "step_ids": set(),
                        "invocation_count": 0,
                        "support_tier": _tier(
                            invocation["executable"], provider, semantics
                        ),
                    },
                )
                record["invocation_count"] += 1
                if technique_id:
                    record["techniques"].add(technique_id)
                scenario_seen.add(key)
                step_seen.add(key)

            for key in step_seen:
                records[key]["step_ids"].add((scenario_index, step.get("order")))
        for key in scenario_seen:
            records[key]["scenario_ids"].add(scenario_index)

    result = []
    for record in records.values():
        result.append(
            {
                "command": record["command"],
                "techniques": sorted(record["techniques"]),
                "scenario_count": len(record["scenario_ids"]),
                "step_count": len(record["step_ids"]),
                "invocation_count": record["invocation_count"],
                "support_tier": record["support_tier"],
            }
        )
    return sorted(result, key=lambda item: (-item["invocation_count"], item["command"]))


def _load_scenarios(paths: list[Path]) -> list[dict[str, Any]]:
    scenarios = []
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, list):
            scenarios.extend(document)
        else:
            scenarios.append(document)
    return scenarios


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect development-only command usage from scenario JSON"
    )
    parser.add_argument("scenario", nargs="+", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            collect_command_usage(_load_scenarios(args.scenario)),
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
