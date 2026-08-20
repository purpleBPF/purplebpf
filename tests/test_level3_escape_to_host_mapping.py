import unittest

from purplebpf.offensive.validator.levels.level2.validator import validate_command
from purplebpf.offensive.validator.levels.level3.mapper import map_actions
from purplebpf.offensive.validator.levels.level3.validator import validate_scenario as validate_level3


def _injected_level2(fact):
    return {
        "steps": [
            {
                "order": 1,
                "raw_command": "synthetic structured evidence",
                "executable": {
                    "raw": "evidence-provider",
                    "normalized": "evidence-provider",
                },
                "argv": [],
                "elements": [],
                "resources": {"requires": [], "produces": []},
                "facts": [fact],
            }
        ]
    }


def _validate_injected(fact):
    return validate_level3(
        {
            "technique_id": "T1611",
            "steps": [{"order": 1, "command": "synthetic structured evidence"}],
        },
        level2_output=_injected_level2(fact),
    )


class EscapeToHostFactMappingTests(unittest.TestCase):
    def test_nsenter_fact_preserves_target_and_maps_without_host_guess(self):
        level2 = validate_command("nsenter -t 1 -m /bin/bash")
        namespace_fact = next(
            fact for fact in level2["facts"] if fact["type"] == "namespace"
        )
        mapped = map_actions(level2)

        self.assertEqual(namespace_fact["identity"], {"target_pid": "1"})
        self.assertEqual(
            namespace_fact["attributes"],
            {"operation": "enter", "kind": "mount"},
        )
        action = mapped["actions"][0]
        self.assertEqual(action["action"], "ENTER_NAMESPACE")
        self.assertEqual(action["context"], {"namespace_type": "mount"})
        self.assertEqual(action["evidence"]["target_pid"], "1")
        self.assertEqual(action["evidence"]["option"], "-m")
        self.assertNotIn("namespace_context", action["context"])

    def test_mount_fact_maps_known_context_without_host_guess(self):
        bind = map_actions(validate_command("mount --bind / /mnt/root"))["actions"][0]
        device = map_actions(validate_command("mount /dev/sda1 /host"))["actions"][0]

        self.assertEqual(bind["action"], "MOUNT_FILESYSTEM")
        self.assertEqual(bind["context"], {"operation": "bind"})
        self.assertEqual(bind["evidence"]["source"], "/")
        self.assertEqual(bind["evidence"]["target"], "/mnt/root")
        self.assertNotIn("target_context", bind["context"])
        self.assertEqual(
            device["context"],
            {"operation": "mount", "source_type": "device"},
        )
        self.assertNotIn("target_context", device["context"])

    def test_explicit_context_is_passed_through_from_structured_fact(self):
        namespace = map_actions(
            _injected_level2(
                {
                    "type": "namespace",
                    "identity": {"target_pid": "42"},
                    "attributes": {
                        "operation": "enter",
                        "kind": "mount",
                        "namespace_context": "host",
                    },
                }
            )["steps"][0]
        )["actions"][0]
        mount = map_actions(
            _injected_level2(
                {
                    "type": "mount",
                    "identity": {"source": "/", "target": "/mnt/root"},
                    "attributes": {
                        "operation": "bind",
                        "target_context": "host",
                    },
                }
            )["steps"][0]
        )["actions"][0]

        self.assertEqual(namespace["context"]["namespace_context"], "host")
        self.assertEqual(mount["context"]["target_context"], "host")


class EscapeToHostEndToEndTests(unittest.TestCase):
    def _validate_command(self, command):
        return validate_level3(
            {
                "technique_id": "T1611",
                "steps": [{"order": 1, "command": command}],
            }
        )

    def test_pid_one_nsenter_is_review_for_missing_host_context(self):
        result = self._validate_command("nsenter -t 1 -m /bin/bash")

        self.assertEqual(result["status"], "REVIEW")
        self.assertIsNone(result["technique_validation"]["matched"])
        self.assertEqual(
            result["technique_validation"]["code"],
            "INSUFFICIENT_ACTION_CONTEXT",
        )
        self.assertNotIn(
            "namespace_context", result["steps"][0]["actions"][0]["context"]
        )

    def test_general_mount_is_review_for_missing_host_context(self):
        result = self._validate_command("mount --bind / /mnt/root")

        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(
            result["technique_validation"]["code"],
            "INSUFFICIENT_ACTION_CONTEXT",
        )
        self.assertNotIn(
            "target_context", result["steps"][0]["actions"][0]["context"]
        )

    def test_host_named_mount_path_does_not_create_host_context(self):
        result = self._validate_command("mount /dev/sda1 /host")

        self.assertEqual(result["status"], "REVIEW")
        self.assertNotIn(
            "target_context", result["steps"][0]["actions"][0]["context"]
        )

    def test_unshare_is_supporting_only_and_never_passes(self):
        result = self._validate_command("unshare --mount")

        self.assertNotEqual(result["status"], "PASS")
        self.assertFalse(result["technique_validation"]["matched"])
        self.assertEqual(
            result["technique_validation"]["code"],
            "TECHNIQUE_ACTION_MISMATCH",
        )
        self.assertEqual(
            result["technique_validation"]["supporting_evidence"][0]["action"],
            "CREATE_NAMESPACE",
        )

    def test_explicit_host_namespace_fact_passes(self):
        result = _validate_injected(
            {
                "type": "namespace",
                "identity": {"target_pid": "42"},
                "attributes": {
                    "operation": "enter",
                    "kind": "mount",
                    "namespace_context": "host",
                },
                "evidence": {"provider": "trusted-environment"},
            }
        )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["technique_validation"]["matched_pattern_id"],
            "enter-host-namespace",
        )

    def test_explicit_host_mount_fact_passes(self):
        result = _validate_injected(
            {
                "type": "mount",
                "identity": {"source": "/", "target": "/mnt/root"},
                "attributes": {
                    "operation": "bind",
                    "target_context": "host",
                },
                "evidence": {"provider": "trusted-environment"},
            }
        )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["technique_validation"]["matched_pattern_id"],
            "mount-host-filesystem",
        )

    def test_explicit_container_namespace_conflicts_and_rejects(self):
        result = _validate_injected(
            {
                "type": "namespace",
                "identity": {"target_pid": "42"},
                "attributes": {
                    "operation": "enter",
                    "kind": "mount",
                    "namespace_context": "container",
                },
            }
        )

        self.assertEqual(result["status"], "REJECT")
        self.assertFalse(result["technique_validation"]["matched"])
        self.assertEqual(
            result["technique_validation"]["code"],
            "TECHNIQUE_ACTION_MISMATCH",
        )

    def test_explicit_container_mount_conflicts_and_rejects(self):
        result = _validate_injected(
            {
                "type": "mount",
                "identity": {"source": "/", "target": "/mnt/root"},
                "attributes": {
                    "operation": "bind",
                    "target_context": "container",
                },
            }
        )

        self.assertEqual(result["status"], "REJECT")
        self.assertEqual(
            result["technique_validation"]["code"],
            "TECHNIQUE_ACTION_MISMATCH",
        )

    def test_unmapped_action_remains_review(self):
        result = self._validate_command("some-unknown-tool --foo")

        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(result["technique_validation"]["code"], "UNMAPPED_ACTION")


if __name__ == "__main__":
    unittest.main()
