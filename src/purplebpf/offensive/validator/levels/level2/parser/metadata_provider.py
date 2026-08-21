"""CLI metadata types and providers used by the argument mapper."""

from __future__ import annotations

import json
import re
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class OptionMetadata:
    names: tuple[str, ...]
    value: str = "none"
    pattern: str | None = None
    value_pattern: str | None = None

    def matches(self, name: str) -> bool:
        return name in self.names or (
            self.pattern is not None and re.fullmatch(self.pattern, name) is not None
        )


@dataclass(frozen=True)
class OperandRuleMetadata:
    """Declarative validation for one positional operand."""

    position: int
    supported_pattern: str
    invalid_patterns: tuple[str, ...] = ()
    when_options_absent: tuple[str, ...] = ()

    def applies(self, matched_options: set[str]) -> bool:
        return not matched_options.intersection(self.when_options_absent)

    def classify(self, value: str) -> bool | None:
        if re.fullmatch(self.supported_pattern, value) is not None:
            return True
        if any(re.fullmatch(pattern, value) for pattern in self.invalid_patterns):
            return False
        return None


@dataclass(frozen=True)
class CommandMetadata:
    name: str
    options: tuple[OptionMetadata, ...]
    min_operands: int = 0
    max_operands: int | None = None
    min_operands_by_option: tuple[tuple[str, int], ...] = ()
    operand_pattern: str | None = None
    operand_rules: tuple[OperandRuleMetadata, ...] = ()
    allow_short_option_clusters: bool = False
    ambiguous_short_option: str = "unmapped"
    known_ambiguous_short_options: frozenset[str] = frozenset()

    def option(self, name: str) -> OptionMetadata | None:
        return next((option for option in self.options if option.matches(name)), None)


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
            provenance = raw.get("provenance")
            if (
                provenance is not None
                and provenance.get("review_status") != "APPROVED"
            ):
                continue
            options = tuple(
                OptionMetadata(
                    names=tuple(option.get("names", [])),
                    value=option.get("value", "none"),
                    pattern=option.get("pattern"),
                    value_pattern=option.get("value_pattern"),
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
                operand_pattern=operands.get("pattern"),
                operand_rules=tuple(
                    OperandRuleMetadata(
                        position=rule["position"],
                        supported_pattern=rule["supported_pattern"],
                        invalid_patterns=tuple(rule.get("invalid_patterns", [])),
                        when_options_absent=tuple(
                            rule.get("when_options_absent", [])
                        ),
                    )
                    for rule in raw.get("operand_rules", [])
                ),
                allow_short_option_clusters=raw.get(
                    "allow_short_option_clusters", False
                ),
                ambiguous_short_option=raw.get(
                    "ambiguous_short_option", "unmapped"
                ),
                known_ambiguous_short_options=(
                    _python_signal_options()
                    if raw.get("ambiguous_short_option_source")
                    == "python_signals"
                    else frozenset()
                ),
            )
        return commands


def _python_signal_options() -> frozenset[str]:
    """Return portable kill-style signal spellings without executing kill."""
    options: set[str] = set()
    valid_numbers = signal.valid_signals()
    for number in valid_numbers:
        if isinstance(number, int):
            options.add(f"-{number}")
    for name in signal.Signals.__members__:
        options.add(f"-{name}")
        if name.startswith("SIG"):
            options.add(f"-{name.removeprefix('SIG')}")
    return frozenset(options)
