"""Local MITRE ATT&CK STIX provider for Level 3 technique lookup."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any


UNKNOWN_TECHNIQUE = "UNKNOWN_TECHNIQUE"


class AttackDataError(RuntimeError):
    """Raised when the local ATT&CK data cannot be loaded safely."""


class AttackProvider:
    """Provide normalized Enterprise ATT&CK technique metadata from local STIX."""

    def __init__(self, data_path: str | Path | None = None):
        default_path = (
            Path(__file__).parents[1]
            / "data"
            / "enterprise-attack-19.2-techniques.json"
        )
        self._data_path = Path(data_path) if data_path is not None else default_path
        self._techniques: dict[str, dict[str, Any]] | None = None

    def get_technique(self, technique_id: str) -> dict[str, Any]:
        """Look up an ATT&CK external ID such as T1611 or T1548.001."""
        if self._techniques is None:
            self._techniques = self._load_techniques()

        normalized_id = (
            technique_id.strip().upper() if isinstance(technique_id, str) else ""
        )
        technique = self._techniques.get(normalized_id)
        if technique is None:
            return {
                "found": False,
                "code": UNKNOWN_TECHNIQUE,
                "technique_id": normalized_id,
            }

        return {"found": True, "technique": deepcopy(technique)}

    def _load_techniques(self) -> dict[str, dict[str, Any]]:
        try:
            with self._data_path.open(encoding="utf-8") as data_file:
                bundle = json.load(data_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise AttackDataError(
                f"failed to load ATT&CK data from {self._data_path}: {exc}"
            ) from exc

        objects = bundle.get("objects")
        if bundle.get("type") != "bundle" or not isinstance(objects, list):
            raise AttackDataError("ATT&CK data must be a STIX bundle with objects")

        attack_patterns = {
            obj["id"]: obj
            for obj in objects
            if obj.get("type") == "attack-pattern" and isinstance(obj.get("id"), str)
        }
        tactics = {
            obj["x_mitre_shortname"]: obj["name"]
            for obj in objects
            if obj.get("type") == "x-mitre-tactic"
            and isinstance(obj.get("x_mitre_shortname"), str)
            and isinstance(obj.get("name"), str)
        }
        parent_by_child = {
            obj["source_ref"]: obj["target_ref"]
            for obj in objects
            if obj.get("type") == "relationship"
            and obj.get("relationship_type") == "subtechnique-of"
            and isinstance(obj.get("source_ref"), str)
            and isinstance(obj.get("target_ref"), str)
        }

        external_id_by_stix: dict[str, str] = {}
        for stix_id, attack_pattern in attack_patterns.items():
            external_id = self._external_id(attack_pattern)
            if external_id is not None:
                external_id_by_stix[stix_id] = external_id

        techniques: dict[str, dict[str, Any]] = {}
        for stix_id, attack_pattern in attack_patterns.items():
            external_id = external_id_by_stix.get(stix_id)
            if external_id is None:
                continue
            if external_id in techniques:
                raise AttackDataError(
                    f"duplicate MITRE ATT&CK external ID: {external_id}"
                )

            parent_stix_id = parent_by_child.get(stix_id)
            techniques[external_id] = {
                "id": external_id,
                "name": attack_pattern.get("name", ""),
                "description": attack_pattern.get("description", ""),
                "tactics": self._normalize_tactics(attack_pattern, tactics),
                "platforms": list(attack_pattern.get("x_mitre_platforms", [])),
                "is_subtechnique": bool(
                    attack_pattern.get("x_mitre_is_subtechnique", False)
                ),
                "parent_id": external_id_by_stix.get(parent_stix_id),
                "deprecated": bool(
                    attack_pattern.get("x_mitre_deprecated", False)
                ),
                "revoked": bool(attack_pattern.get("revoked", False)),
                "stix_id": stix_id,
            }

        return techniques

    @staticmethod
    def _external_id(attack_pattern: dict[str, Any]) -> str | None:
        for reference in attack_pattern.get("external_references", []):
            if reference.get("source_name") == "mitre-attack" and isinstance(
                reference.get("external_id"), str
            ):
                return reference["external_id"]
        return None

    @staticmethod
    def _normalize_tactics(
        attack_pattern: dict[str, Any], tactic_names: dict[str, str]
    ) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []
        seen: set[str] = set()
        for phase in attack_pattern.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            shortname = phase.get("phase_name")
            if shortname in seen or shortname not in tactic_names:
                continue
            seen.add(shortname)
            normalized.append(
                {"name": tactic_names[shortname], "shortname": shortname}
            )
        return normalized
