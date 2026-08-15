"""Build normalized, ATT&CK-independent facts from declarative command rules."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit


Fact = dict[str, Any]
Extractor = Callable[
    [dict[str, Any], dict[str, Any], dict[str, Any]], tuple[list[Fact], bool]
]


class JsonSemanticRuleProvider:
    """Load fact extractors and shared classifiers from resource rules."""

    def __init__(self, path: str | Path | None = None):
        default_path = Path(__file__).parents[1] / "rules" / "resource_rules.json"
        self._path = Path(path) if path is not None else default_path
        self._document: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any]:
        if self._document is None:
            with self._path.open(encoding="utf-8") as rule_file:
                self._document = json.load(rule_file)
        return self._document

    def get(self, executable: str) -> dict[str, Any] | None:
        return self._load().get("commands", {}).get(executable)

    def classifiers(self) -> dict[str, Any]:
        return self._load().get("classifiers", {})


def _operands(command: dict[str, Any]) -> dict[int, str]:
    return {
        element["position"]: element["raw"]
        for element in command.get("elements", [])
        if element.get("type") == "operand"
    }


def _options(command: dict[str, Any]) -> list[str]:
    return [
        element["raw"]
        for element in command.get("elements", [])
        if element.get("type") == "option"
    ]


def _option_values(command: dict[str, Any]) -> dict[str, str]:
    return {
        element["option"]: element["raw"]
        for element in command.get("elements", [])
        if element.get("type") == "option_value"
    }


def _first_option_value(command: dict[str, Any], names: list[str]) -> str | None:
    values = _option_values(command)
    return next((values[name] for name in names if name in values), None)


def _path_class(path: str, classifiers: dict[str, Any]) -> str | None:
    for name, prefixes in classifiers.get("path_prefix_groups", {}).items():
        if any(path.startswith(prefix) for prefix in prefixes):
            return name
    return None


def _fact(
    fact_type: str,
    *,
    identity: dict[str, str] | None = None,
    attributes: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
) -> Fact:
    result: Fact = {"type": fact_type}
    if identity:
        result["identity"] = identity
    if attributes:
        result["attributes"] = attributes
    if evidence:
        result["evidence"] = evidence
    return result


def _permission_changes(mode: str) -> list[dict[str, str]] | None:
    if re.fullmatch(r"[0-7]{3,4}", mode):
        special = int(mode[0], 8) if len(mode) == 4 else 0
        changes = []
        if special & 4:
            changes.append({"permission": "setuid", "operation": "add"})
        if special & 2:
            changes.append({"permission": "setgid", "operation": "add"})
        if changes:
            return changes
        return [{"permission": "mode", "operation": "set", "value": mode}]

    changes: list[dict[str, str]] = []
    for clause in mode.split(","):
        match = re.fullmatch(r"([ugoa]*)([+=-])([rwxXst]+)", clause)
        if match is None:
            return None
        who, operator, permissions = match.groups()
        operation = {"+": "add", "-": "remove", "=": "set"}[operator]
        subjects = set(who) if who else {"u", "g", "o"}
        if "a" in subjects:
            subjects = {"u", "g", "o"}
        if "s" in permissions:
            if "u" in subjects:
                changes.append({"permission": "setuid", "operation": operation})
            if "g" in subjects:
                changes.append({"permission": "setgid", "operation": operation})
        if "x" in permissions:
            changes.append({"permission": "execute", "operation": operation})
    return changes or None


def _extract_permission_mode(
    command: dict[str, Any], spec: dict[str, Any], classifiers: dict[str, Any]
) -> tuple[list[Fact], bool]:
    operands = _operands(command)
    mode = operands.get(spec.get("mode_operand", 1))
    targets = [
        value
        for position, value in sorted(operands.items())
        if position >= spec.get("targets_from", 2)
    ]
    changes = _permission_changes(mode) if mode is not None else None
    if not changes or not targets:
        return [], False

    facts = []
    for target in targets:
        for change in changes:
            attributes = dict(change)
            path_type = _path_class(target, classifiers)
            if path_type is not None:
                attributes["path_type"] = path_type
            facts.append(
                _fact(
                    "permission",
                    identity={"path": target},
                    attributes=attributes,
                    evidence={"mode": mode},
                )
            )
    return facts, True


def _extract_option_map(
    command: dict[str, Any], spec: dict[str, Any], classifiers: dict[str, Any]
) -> tuple[list[Fact], bool]:
    del classifiers
    mapping = spec["values"]
    facts = []
    for option in _options(command):
        value = mapping.get(option)
        if value is None:
            continue
        facts.append(
            _fact(
                spec["fact_type"],
                attributes={**spec.get("attributes", {}), spec["attribute"]: value},
                evidence={"option": option},
            )
        )
    return facts, bool(facts)


def _extract_option_value(
    command: dict[str, Any], spec: dict[str, Any], classifiers: dict[str, Any]
) -> tuple[list[Fact], bool]:
    del classifiers
    value = _first_option_value(command, spec["options"])
    if value is None:
        return [], False
    option_values = _option_values(command)
    matched_option = next(
        option for option in spec["options"] if option in option_values
    )
    return [
        _fact(
            spec["fact_type"],
            identity={spec["identity"]: value},
            attributes=spec.get("attributes"),
            evidence={"option": matched_option},
        )
    ], True


def _extract_mount(
    command: dict[str, Any], spec: dict[str, Any], classifiers: dict[str, Any]
) -> tuple[list[Fact], bool]:
    del classifiers
    operands = _operands(command)
    source = _first_option_value(command, spec.get("source_options", []))
    if source is None:
        source = operands.get(spec.get("source_operand", 1))
    target = _first_option_value(command, spec.get("target_options", []))
    if target is None:
        target = operands.get(spec.get("target_operand", 2))
    if source is None or target is None:
        return [], False
    present_options = set(_options(command))
    operation = (
        "bind"
        if present_options.intersection(spec.get("bind_options", []))
        else "mount"
    )
    attributes = {"operation": operation}
    if source.startswith("/dev/"):
        attributes["source_type"] = "device"
    filesystem_type = _first_option_value(command, spec.get("type_options", []))
    if filesystem_type is not None:
        attributes["filesystem_type"] = filesystem_type
    return [
        _fact(
            "mount",
            identity={"source": source, "target": target},
            attributes=attributes,
        )
    ], True


def _extract_url_transfer(
    command: dict[str, Any], spec: dict[str, Any], classifiers: dict[str, Any]
) -> tuple[list[Fact], bool]:
    url_options = set(spec.get("url_options", []))
    urls = [
        element["raw"]
        for element in command.get("elements", [])
        if element.get("type") == "operand"
        or (
            element.get("type") == "option_value"
            and element.get("option") in url_options
        )
    ]
    output = _first_option_value(command, spec.get("output_options", []))
    method = _first_option_value(command, spec.get("request_options", []))
    endpoint_classes = classifiers.get("endpoint_addresses", {})
    facts: list[Fact] = []
    for raw_url in urls:
        parsed = urlsplit(raw_url)
        if not parsed.scheme or not parsed.hostname:
            continue
        attributes: dict[str, Any] = {
            "protocol": parsed.scheme.lower(),
            "address": parsed.hostname,
        }
        endpoint_class = endpoint_classes.get(parsed.hostname)
        if endpoint_class is not None:
            attributes["class"] = endpoint_class
        if method is not None:
            attributes["request_method"] = method.upper()
        facts.append(
            _fact(
                "endpoint",
                identity={"url": raw_url},
                attributes=attributes,
            )
        )
        transfer_attributes: dict[str, Any] = {"direction": "download"}
        transfer_identity = {"source": raw_url}
        if output is not None:
            transfer_identity["output_path"] = output
            path_type = _path_class(output, classifiers)
            if path_type is not None:
                transfer_attributes["output_path_type"] = path_type
        elif set(_options(command)).intersection(spec.get("remote_name_options", [])):
            transfer_attributes["output"] = "remote_name"
        facts.append(
            _fact(
                "transfer",
                identity=transfer_identity,
                attributes=transfer_attributes,
            )
        )
    return facts, bool(facts)


def _normalize_signal(option: str | None) -> str | None:
    if option is None:
        return "SIGTERM"
    value = option.removeprefix("-").upper()
    aliases = {"9": "SIGKILL", "KILL": "SIGKILL", "SIGKILL": "SIGKILL"}
    aliases.update({"TERM": "SIGTERM", "SIGTERM": "SIGTERM"})
    return aliases.get(value)


def _extract_process_signal(
    command: dict[str, Any], spec: dict[str, Any], classifiers: dict[str, Any]
) -> tuple[list[Fact], bool]:
    del spec, classifiers
    options = _options(command)
    signal = _normalize_signal(options[0] if options else None)
    operands = _operands(command)
    if signal is None or not operands:
        return [], False
    return [
        _fact(
            "process_signal",
            identity={"target_pid": pid},
            attributes={"signal": signal},
        )
        for _, pid in sorted(operands.items())
    ], True


_EXTRACTORS: dict[str, Extractor] = {
    "permission_mode": _extract_permission_mode,
    "option_map": _extract_option_map,
    "option_value": _extract_option_value,
    "mount": _extract_mount,
    "url_transfer": _extract_url_transfer,
    "process_signal": _extract_process_signal,
}


def map_facts(
    command_result: dict[str, Any],
    rule_provider: JsonSemanticRuleProvider | None = None,
) -> dict[str, Any]:
    """Return normalized facts and whether required semantic evidence resolved."""
    provider = rule_provider or JsonSemanticRuleProvider()
    executable = command_result["executable"]["normalized"]
    rule = provider.get(executable)
    if rule is None:
        return {
            "facts": [],
            "fact_validation": {"resolved": True, "code": None},
        }

    classifiers = provider.classifiers()
    facts: list[Fact] = []
    unresolved = False
    for specification in rule.get("facts", []):
        extractor = _EXTRACTORS[specification["extractor"]]
        extracted, matched = extractor(command_result, specification, classifiers)
        facts.extend(extracted)
        if specification.get("required", False) and not matched:
            unresolved = True

    return {
        "facts": facts,
        "fact_validation": {
            "resolved": not unresolved,
            "code": "UNRESOLVED_SEMANTIC" if unresolved else None,
        },
    }
