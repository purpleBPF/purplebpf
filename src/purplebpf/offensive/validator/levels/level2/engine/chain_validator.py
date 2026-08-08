"""Ordered dependency validation for mapped Level 2 resources."""

from __future__ import annotations

from typing import Any

from .resource import Resource


class ResourceState:
    """Resources produced by successfully connected earlier scenario steps."""

    def __init__(self) -> None:
        self._resources: dict[str, Resource] = {}

    def contains(self, resource: Resource) -> bool:
        return resource.key() in self._resources

    def add(self, resource: Resource) -> None:
        self._resources[resource.key()] = resource

    def to_list(self) -> list[dict[str, Any]]:
        return [self._resources[key].to_dict() for key in sorted(self._resources)]


def validate_dependencies(
    steps: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate step requirements in order and return errors and final state."""
    state = ResourceState()
    errors: list[dict[str, Any]] = []

    for step in steps:
        if step["status"] != "PASS":
            continue

        required = [
            Resource.from_dict(resource)
            for resource in step["resources"]["requires"]
        ]
        missing = [resource for resource in required if not state.contains(resource)]
        if missing:
            step["status"] = "REJECT"
            for resource in missing:
                error = {
                    "step": step["order"],
                    "stage": "dependency_check",
                    "code": "MISSING_CHAIN_RESOURCE",
                    "command": step["command"],
                    "resource": resource.to_dict(),
                    "message": "required resource was not produced by an earlier step",
                }
                step["errors"].append(error)
                errors.append(error)
            continue

        for resource in step["resources"]["produces"]:
            state.add(Resource.from_dict(resource))

    return errors, state.to_list()
