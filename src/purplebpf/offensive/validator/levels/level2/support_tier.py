"""Resolve Level 2 analysis depth from approved metadata and semantic rules."""

from __future__ import annotations

from .engine.semantic_mapper import JsonSemanticRuleProvider
from .parser.metadata_provider import JsonMetadataProvider, MetadataProvider


def resolve_support_tier(
    executable: str,
    metadata_provider: MetadataProvider | None = None,
    semantic_rule_provider: JsonSemanticRuleProvider | None = None,
) -> str:
    """Return full, metadata, or generic without a command-name allowlist."""
    metadata = metadata_provider or JsonMetadataProvider()
    if metadata.get(executable) is None:
        return "generic"
    semantics = semantic_rule_provider or JsonSemanticRuleProvider()
    rule = semantics.get(executable)
    if rule is not None and bool(rule.get("facts")):
        return "full"
    return "metadata"
