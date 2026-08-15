"""Declarative Technique-to-Action rule provider."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class TechniqueRuleError(RuntimeError):
    """Raised when Technique Action rules cannot be loaded safely."""


class JsonTechniqueRuleProvider:
    """Load Technique Action patterns from a versioned JSON document."""

    def __init__(self, path: str | Path | None = None):
        default_path = (
            Path(__file__).parents[1] / "rules" / "technique_action_rules.json"
        )
        self._path = Path(path) if path is not None else default_path
        self._document: dict[str, Any] | None = None

    def get(self, technique_id: str) -> dict[str, Any] | None:
        if self._document is None:
            self._document = self._load()
        return self._document["techniques"].get(technique_id)

    def _load(self) -> dict[str, Any]:
        try:
            with self._path.open(encoding="utf-8") as rule_file:
                document = json.load(rule_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise TechniqueRuleError(
                f"failed to load Technique Action rules from {self._path}: {exc}"
            ) from exc

        if document.get("schema_version") != 1 or not isinstance(
            document.get("techniques"), dict
        ):
            raise TechniqueRuleError("invalid Technique Action rule document")
        return document
