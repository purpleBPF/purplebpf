"""Resource value object used by Level 2 chain validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Resource:
    """A hashable resource identified by its type and identity fields."""

    type: str
    identity_items: tuple[tuple[str, str], ...]

    @classmethod
    def create(cls, resource_type: str, identity: dict[str, str]) -> "Resource":
        return cls(resource_type, tuple(sorted(identity.items())))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Resource":
        return cls.create(value["type"], value["identity"])

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "identity": dict(self.identity_items)}

    def key(self) -> str:
        """Return a deterministic representation suitable for state lookup."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
