"""Classify high-confidence credential file targets from declarative rules."""

from __future__ import annotations

import json
import posixpath
from pathlib import Path
from typing import Any


class CredentialTargetRuleError(RuntimeError):
    """Raised when credential target rules cannot be loaded safely."""


class JsonCredentialTargetClassifier:
    """Match lexical shell paths against reviewed credential target rules."""

    def __init__(self, path: str | Path | None = None):
        default_path = Path(__file__).parents[1] / "rules" / "credential_targets.json"
        self._path = Path(path) if path is not None else default_path
        self._document: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any]:
        if self._document is not None:
            return self._document
        try:
            with self._path.open(encoding="utf-8") as rule_file:
                document = json.load(rule_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise CredentialTargetRuleError(
                f"failed to load credential target rules from {self._path}: {exc}"
            ) from exc

        if document.get("schema_version") != 1:
            raise CredentialTargetRuleError(
                "unsupported credential target rule schema"
            )
        targets = document.get("targets")
        if not isinstance(targets, list):
            raise CredentialTargetRuleError("credential targets must be a list")

        seen: set[str] = set()
        for target in targets:
            if not isinstance(target, dict) or not isinstance(target.get("id"), str):
                raise CredentialTargetRuleError("invalid credential target rule")
            if target["id"] in seen:
                raise CredentialTargetRuleError(
                    f"duplicate credential target rule: {target['id']}"
                )
            seen.add(target["id"])
            match = target.get("match")
            if not isinstance(match, dict) or len(match) != 1:
                raise CredentialTargetRuleError(
                    f"invalid match in credential target rule: {target['id']}"
                )
            kind, value = next(iter(match.items()))
            if kind not in {"exact_path", "path_suffix"} or not isinstance(
                value, str
            ):
                raise CredentialTargetRuleError(
                    f"unsupported match in credential target rule: {target['id']}"
                )
            if target.get("data_type") != "credential" or not isinstance(
                target.get("credential_type"), str
            ):
                raise CredentialTargetRuleError(
                    f"invalid classification in credential target rule: {target['id']}"
                )

        self._document = document
        return document

    @staticmethod
    def normalize(path: str) -> str | None:
        """Lexically normalize without expanding users, variables, or symlinks."""
        if not isinstance(path, str) or not path or "\x00" in path:
            return None
        return posixpath.normpath(path)

    def classify(self, path: str) -> dict[str, Any]:
        normalized = self.normalize(path)
        if normalized is None:
            return {"classified": False}

        for target in self._load()["targets"]:
            match = target["match"]
            if "exact_path" in match:
                expected = self.normalize(match["exact_path"])
                matched = normalized == expected
            else:
                suffix = match["path_suffix"]
                matched = normalized.endswith(suffix)
            if matched:
                return {
                    "classified": True,
                    "data_type": target["data_type"],
                    "credential_type": target["credential_type"],
                    "rule_id": target["id"],
                    "normalized_path": normalized,
                }
        return {"classified": False, "normalized_path": normalized}
