"""ExplainShell-style argv matching against command metadata."""

from __future__ import annotations

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


def _map_known_command(
    argv: list[str], metadata: CommandMetadata
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    elements: list[dict[str, Any]] = []
    operand_position = 0
    matched_options: set[str] = set()
    options_enabled = True
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
                if token.startswith("-") and not token.startswith("--") and len(token) > 2:
                    return elements, _validation(None, "UNMAPPED_ARGUMENT", token)
                return elements, _validation(False, "INVALID_OPTION", token)

            elements.append({"raw": option_name, "type": "option"})
            matched_options.add(option_name)

            if attached_value is not None:
                if option.value == "none":
                    return elements, _validation(False, "INVALID_OPTION", token)
                if not attached_value:
                    return elements, _validation(False, "INVALID_ARGUMENT", token)
                elements.append(
                    {
                        "raw": attached_value,
                        "type": "option_value",
                        "option": option_name,
                    }
                )
            elif option.value == "required":
                if index + 1 >= len(argv):
                    return elements, _validation(
                        False, "INVALID_ARGUMENT", option_name
                    )
                index += 1
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
        return elements, _validation(False, "INVALID_ARGUMENT")
    if metadata.max_operands is not None and operand_position > metadata.max_operands:
        return elements, _validation(False, "INVALID_ARGUMENT")

    return elements, _validation(True)


def map_arguments(
    parsed_command: dict[str, Any],
    metadata_provider: MetadataProvider | None = None,
) -> dict[str, Any]:
    """Map parsed argv elements and perform the current CLI validity checks."""
    provider = metadata_provider or JsonMetadataProvider()
    executable = parsed_command["executable"]
    argv = parsed_command["argv"]
    metadata = provider.get(executable["normalized"])

    if metadata is None:
        return {
            "raw_command": parsed_command["raw_command"],
            "executable": executable,
            "elements": [],
            "cli_validation": _validation(None, "UNSUPPORTED_COMMAND"),
        }

    elements, cli_validation = _map_known_command(argv, metadata)
    return {
        "raw_command": parsed_command["raw_command"],
        "executable": executable,
        "elements": elements,
        "cli_validation": cli_validation,
    }
