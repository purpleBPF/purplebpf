"""ExplainShell-style argv matching against command metadata."""

from __future__ import annotations

import re
from typing import Any

from .metadata_provider import (
    CommandMetadata,
    JsonMetadataProvider,
    MetadataProvider,
    OptionMetadata,
)


def _validation(
    valid: bool | None,
    code: str | None = None,
    element: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"valid": valid, "code": code}
    if element is not None:
        result["element"] = element
    return result


def _merge_issue(
    current: dict[str, Any] | None,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Keep the first issue, but let a definite invalid override uncertainty."""
    if current is None or (
        current["valid"] is None and candidate["valid"] is False
    ):
        return candidate
    return current


def _option_and_attached_value(
    token: str, metadata: CommandMetadata
) -> tuple[OptionMetadata | None, str, str | None]:
    if token.startswith("--") and "=" in token:
        name, value = token.split("=", 1)
        return metadata.option(name), name, value

    exact = metadata.option(token)
    if exact is not None:
        return exact, token, None

    if token.startswith("-") and not token.startswith("--") and len(token) > 2:
        short_name = token[:2]
        option = metadata.option(short_name)
        if option is not None and option.value == "required":
            return option, short_name, token[2:]

    return None, token, None


def _short_option_cluster(
    token: str, metadata: CommandMetadata
) -> list[tuple[OptionMetadata, str, str | None]] | None:
    if (
        not metadata.allow_short_option_clusters
        or not token.startswith("-")
        or token.startswith("--")
        or len(token) <= 2
    ):
        return None
    cluster = token[1:]
    expanded = []
    for index, character in enumerate(cluster):
        name = f"-{character}"
        option = metadata.option(name)
        if option is None:
            return None
        remainder = cluster[index + 1 :]
        if option.value == "optional_attached":
            return None
        if option.value == "required":
            expanded.append((option, name, remainder or None))
            return expanded
        expanded.append((option, name, None))
    return expanded


def _map_known_command(
    argv: list[str], metadata: CommandMetadata
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    elements: list[dict[str, Any]] = []
    operand_position = 0
    matched_options: set[str] = set()
    options_enabled = True
    issue: dict[str, Any] | None = None
    index = 0

    while index < len(argv):
        token = argv[index]

        if options_enabled and token == "--":
            options_enabled = False
            index += 1
            continue

        if options_enabled and token.startswith("-") and token != "-":
            option, option_name, attached_value = _option_and_attached_value(
                token, metadata
            )
            if option is None:
                cluster = _short_option_cluster(token, metadata)
                if cluster is not None:
                    for cluster_option, cluster_name, cluster_value in cluster:
                        elements.append({"raw": cluster_name, "type": "option"})
                        matched_options.add(cluster_name)
                        if cluster_option.value != "required":
                            continue
                        value = cluster_value
                        if value is None:
                            if index + 1 >= len(argv):
                                issue = _merge_issue(
                                    issue,
                                    _validation(
                                        False, "INVALID_ARGUMENT", cluster_name
                                    ),
                                )
                                continue
                            index += 1
                            value = argv[index]
                        if (
                            cluster_option.value_pattern is not None
                            and re.fullmatch(cluster_option.value_pattern, value)
                            is None
                        ):
                            issue = _merge_issue(
                                issue,
                                _validation(False, "INVALID_ARGUMENT", value),
                            )
                        elements.append(
                            {
                                "raw": value,
                                "type": "option_value",
                                "option": cluster_name,
                            }
                        )
                    index += 1
                    continue
                if (
                    token.startswith("-")
                    and not token.startswith("--")
                    and len(token) > 2
                ):
                    invalid = (
                        metadata.ambiguous_short_option == "invalid"
                        and token not in metadata.known_ambiguous_short_options
                    )
                    issue = _merge_issue(
                        issue,
                        _validation(
                            False if invalid else None,
                            "INVALID_OPTION" if invalid else "UNMAPPED_ARGUMENT",
                            token,
                        ),
                    )
                else:
                    issue = _merge_issue(
                        issue, _validation(False, "INVALID_OPTION", token)
                    )
                index += 1
                continue

            elements.append({"raw": option_name, "type": "option"})
            matched_options.add(option_name)

            if attached_value is not None:
                if option.value == "none":
                    issue = _merge_issue(
                        issue, _validation(False, "INVALID_OPTION", token)
                    )
                    index += 1
                    continue
                if not attached_value:
                    issue = _merge_issue(
                        issue, _validation(False, "INVALID_ARGUMENT", token)
                    )
                    index += 1
                    continue
                if option.value_pattern is not None and re.fullmatch(
                    option.value_pattern, attached_value
                ) is None:
                    issue = _merge_issue(
                        issue,
                        _validation(False, "INVALID_ARGUMENT", attached_value),
                    )
                elements.append(
                    {
                        "raw": attached_value,
                        "type": "option_value",
                        "option": option_name,
                    }
                )
            elif option.value == "required":
                if index + 1 >= len(argv):
                    issue = _merge_issue(
                        issue,
                        _validation(False, "INVALID_ARGUMENT", option_name),
                    )
                else:
                    index += 1
                    if option.value_pattern is not None and re.fullmatch(
                        option.value_pattern, argv[index]
                    ) is None:
                        issue = _merge_issue(
                            issue,
                            _validation(False, "INVALID_ARGUMENT", argv[index]),
                        )
                    elements.append(
                        {
                            "raw": argv[index],
                            "type": "option_value",
                            "option": option_name,
                        }
                    )

            index += 1
            continue

        operand_position += 1
        if metadata.operand_pattern is not None and re.fullmatch(
            metadata.operand_pattern, token
        ) is None:
            issue = _merge_issue(
                issue, _validation(False, "INVALID_ARGUMENT", token)
            )
        elements.append(
            {"raw": token, "type": "operand", "position": operand_position}
        )
        index += 1

    minimum_operands = metadata.min_operands
    for option_name, override in metadata.min_operands_by_option:
        if option_name in matched_options:
            minimum_operands = override
            break

    if operand_position < minimum_operands:
        issue = _merge_issue(issue, _validation(False, "INVALID_ARGUMENT"))
    if metadata.max_operands is not None and operand_position > metadata.max_operands:
        issue = _merge_issue(issue, _validation(False, "INVALID_ARGUMENT"))

    operands = {
        element["position"]: element["raw"]
        for element in elements
        if element["type"] == "operand"
    }
    for rule in metadata.operand_rules:
        value = operands.get(rule.position)
        if value is None or not rule.applies(matched_options):
            continue
        classification = rule.classify(value)
        if classification is False:
            issue = _merge_issue(
                issue, _validation(False, "INVALID_ARGUMENT", value)
            )
        elif classification is None:
            issue = _merge_issue(
                issue, _validation(None, "UNMAPPED_ARGUMENT", value)
            )

    return elements, issue or _validation(True)


def map_arguments(
    parsed_command: dict[str, Any],
    metadata_provider: MetadataProvider | None = None,
) -> dict[str, Any]:
    """Map parsed argv elements and perform the current CLI validity checks."""
    provider = metadata_provider or JsonMetadataProvider()
    executable = parsed_command["executable"]
    argv = parsed_command["argv"]
    metadata = provider.get(executable["normalized"])

    redirect_data = (
        {"redirects": parsed_command["redirects"]}
        if parsed_command.get("redirects")
        else {}
    )

    if metadata is None:
        return {
            "raw_command": parsed_command["raw_command"],
            "executable": executable,
            "argv": argv,
            **redirect_data,
            "support_tier": "generic",
            "elements": [],
            "cli_validation": _validation(None, "UNSUPPORTED_COMMAND"),
        }

    elements, cli_validation = _map_known_command(argv, metadata)
    return {
        "raw_command": parsed_command["raw_command"],
        "executable": executable,
        "argv": argv,
        **redirect_data,
        "support_tier": "metadata",
        "elements": elements,
        "cli_validation": cli_validation,
    }
