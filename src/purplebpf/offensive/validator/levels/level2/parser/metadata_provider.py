"""CLI metadata types and providers used by the argument mapper."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class OptionMetadata:
    names: tuple[str, ...]
    value: str = "none"


@dataclass(frozen=True)
class CommandMetadata:
    name: str
    options: tuple[OptionMetadata, ...]
    min_operands: int = 0
    max_operands: int | None = None
    min_operands_by_option: tuple[tuple[str, int], ...] = ()

    def option(self, name: str) -> OptionMetadata | None:
        return next((option for option in self.options if name in option.names), None)


class MetadataProvider(Protocol):
    """Lookup boundary for replaceable CLI metadata sources."""

    def get(self, executable: str) -> CommandMetadata | None:
        """Return trusted metadata for an executable, or None if unsupported."""


class JsonMetadataProvider:
    """Load the MVP command specifications from a versioned JSON file."""

    def __init__(self, path: str | Path | None = None):
        default_path = Path(__file__).parents[1] / "rules" / "cli_metadata.json"
        self._path = Path(path) if path is not None else default_path
        self._commands: dict[str, CommandMetadata] | None = None

    def get(self, executable: str) -> CommandMetadata | None:
        if self._commands is None:
            self._commands = self._load()
        return self._commands.get(executable)

    def _load(self) -> dict[str, CommandMetadata]:
        with self._path.open(encoding="utf-8") as metadata_file:
            document = json.load(metadata_file)

        commands: dict[str, CommandMetadata] = {}
        for name, raw in document["commands"].items():
            options = tuple(
                OptionMetadata(
                    names=tuple(option["names"]),
                    value=option.get("value", "none"),
                )
                for option in raw.get("options", [])
            )
            operands = raw.get("operands", {})
            commands[name] = CommandMetadata(
                name=name,
                options=options,
                min_operands=operands.get("min", 0),
                max_operands=operands.get("max"),
                min_operands_by_option=tuple(
                    raw.get("min_operands_by_option", {}).items()
                ),
            )
        return commands
