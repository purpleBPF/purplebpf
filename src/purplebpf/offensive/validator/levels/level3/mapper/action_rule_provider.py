"""Declarative Action Mapping rule provider."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ActionRuleError(RuntimeError):
    """Raised when Action Mapping rules cannot be loaded safely."""


class JsonActionRuleProvider:
    """Load the versioned Action vocabulary and mapping rules from JSON."""

    def __init__(self, path: str | Path | None = None):
        default_path = Path(__file__).parents[1] / "rules" / "action_rules.json"
        self._path = Path(path) if path is not None else default_path
        self._document: dict[str, Any] | None = None

    def get_document(self) -> dict[str, Any]:
        if self._document is None:
            self._document = self._load()
        return self._document

    def _load(self) -> dict[str, Any]:
        try:
            with self._path.open(encoding="utf-8") as rule_file:
                document = json.load(rule_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise ActionRuleError(
                f"failed to load Action Mapping rules from {self._path}: {exc}"
            ) from exc

        if document.get("schema_version") != 1:
            raise ActionRuleError("unsupported Action Mapping rule schema")
        expected_types = {
            "action_vocabulary": list,
            "context_vocabulary": list,
            "path_groups": dict,
            "rules": list,
        }
        for field, expected_type in expected_types.items():
            if not isinstance(document.get(field), expected_type):
                raise ActionRuleError(f"invalid Action Mapping rule field: {field}")
        return document
