import json
import unittest
from pathlib import Path

from purplebpf.offensive.validator.levels.level2.validator import validate_command, validate_scenario
from purplebpf.offensive.validator.levels.level3.mapper import map_actions
from purplebpf.offensive.validator.levels.level2.support_tier import resolve_support_tier


def facts(command: str, fact_type: str):
    result = validate_command(command)
    return result, [fact for fact in result["facts"] if fact["type"] == fact_type]


class Tier1CommandTests(unittest.TestCase):
    def assert_full_support(self, result):
        self.assertEqual(result["support_tier"], "full")
        self.assertTrue(result["cli_validation"]["valid"])
        self.assertTrue(result["fact_validation"]["resolved"])
        self.assertEqual(result["analysis"]["semantic"], "resolved")

    def test_chmod_modes(self):
        cases = {
            "chmod u+s /tmp/rootsh": [("setuid", "add")],
            "chmod g+s /tmp/file": [("setgid", "add")],
            "chmod ug+s /tmp/file": [("setuid", "add"), ("setgid", "add")],
            "chmod u-s /tmp/rootsh": [("setuid", "remove")],
            "chmod 4755 /tmp/rootsh": [("setuid", "add")],
            "chmod 2755 /tmp/file": [("setgid", "add")],
            "chmod +x /tmp/a": [("execute", "add")],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                result, mapped = facts(command, "permission")
                self.assert_full_support(result)
                actual = [
                    (fact["attributes"]["permission"], fact["attributes"]["operation"])
                    for fact in mapped
                ]
                self.assertEqual(actual, expected)
                self.assertEqual(result["resources"]["requires"][0]["type"], "file")

    def test_unshare_namespaces(self):
        cases = {
            "unshare --mount": ["mount"],
            "unshare --user": ["user"],
            "unshare --mount --user /bin/bash": ["mount", "user"],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                result, mapped = facts(command, "namespace")
                self.assert_full_support(result)
                self.assertEqual(
                    [fact["attributes"]["kind"] for fact in mapped], expected
                )
                self.assertTrue(
                    all(fact["attributes"]["operation"] == "create" for fact in mapped)
                )

    def test_nsenter_target_and_namespace(self):
        cases = {
            "nsenter -t 1 -m /bin/bash": ("1", "mount"),
            "nsenter --target 123 --net /bin/sh": ("123", "net"),
        }
        for command, (pid, kind) in cases.items():
            with self.subTest(command=command):
                result = validate_command(command)
                self.assert_full_support(result)
                process = next(f for f in result["facts"] if f["type"] == "process")
                namespace = next(
                    f for f in result["facts"] if f["type"] == "namespace"
                )
                self.assertEqual(process["identity"]["target_pid"], pid)
                self.assertEqual(
                    namespace["attributes"], {"operation": "enter", "kind": kind}
                )
                self.assertNotIn("host", json.dumps(result))

    def test_mount_forms(self):
        cases = {
            "mount /dev/sda1 /host": {"operation": "mount", "source_type": "device"},
            "mount -t ext4 /dev/sda1 /host": {
                "operation": "mount",
                "source_type": "device",
                "filesystem_type": "ext4",
            },
            "mount --bind / /host": {"operation": "bind"},
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                result, mapped = facts(command, "mount")
                self.assert_full_support(result)
                self.assertEqual(mapped[0]["attributes"], expected)
                self.assertNotIn("target_context", json.dumps(result))

    def test_curl_endpoint_and_transfer(self):
        metadata, endpoints = facts(
            "curl http://169.254.169.254/latest/meta-data/", "endpoint"
        )
        self.assert_full_support(metadata)
        self.assertEqual(
            endpoints[0]["attributes"],
            {
                "protocol": "http",
                "address": "169.254.169.254",
                "class": "cloud_metadata",
            },
        )

        output, transfers = facts(
            "curl -o /tmp/payload https://example.com/a", "transfer"
        )
        self.assert_full_support(output)
        self.assertEqual(transfers[0]["identity"]["output_path"], "/tmp/payload")
        self.assertEqual(transfers[0]["attributes"]["direction"], "download")
        self.assertEqual(output["resources"]["produces"][0]["type"], "file")

        request, endpoints = facts("curl -X GET https://example.com/", "endpoint")
        self.assert_full_support(request)
        self.assertEqual(endpoints[0]["attributes"]["request_method"], "GET")

    def test_kill_signals(self):
        cases = {
            "kill 1234": "SIGTERM",
            "kill -9 1234": "SIGKILL",
            "kill -SIGKILL 1234": "SIGKILL",
            "kill -TERM 1234": "SIGTERM",
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                result, mapped = facts(command, "process_signal")
                self.assert_full_support(result)
                self.assertEqual(mapped[0]["identity"]["target_pid"], "1234")
                self.assertEqual(mapped[0]["attributes"]["signal"], expected)
                self.assertNotIn("process_type", json.dumps(result))

    def test_outside_subset_is_reviewable_not_guessed(self):
        chmod = validate_command("chmod a=rwX /tmp/file")
        self.assertTrue(chmod["cli_validation"]["valid"])
        self.assertFalse(chmod["fact_validation"]["resolved"])
        self.assertEqual(chmod["fact_validation"]["code"], "UNRESOLVED_SEMANTIC")

        unshare = validate_command("unshare --cgroup")
        self.assertTrue(unshare["cli_validation"]["valid"])
        self.assertFalse(unshare["fact_validation"]["resolved"])

        kill = validate_command("kill -HUP 1234")
        self.assertIsNone(kill["cli_validation"]["valid"])
        self.assertEqual(kill["cli_validation"]["code"], "UNMAPPED_ARGUMENT")

        scenario = validate_scenario(
            {
                "steps": [
                    {"order": 1, "command": "touch /tmp/file"},
                    {"order": 2, "command": "chmod a=rwX /tmp/file"},
                ]
            }
        )
        self.assertEqual(scenario["status"], "REVIEW")
        self.assertEqual(scenario["errors"][0]["code"], "UNRESOLVED_SEMANTIC")

    def test_invalid_values_remain_invalid(self):
        invalid_option = validate_command("unshare --definitely-invalid-option")
        self.assertFalse(invalid_option["cli_validation"]["valid"])
        self.assertEqual(invalid_option["cli_validation"]["code"], "INVALID_OPTION")

        invalid_pid = validate_command("kill not-a-pid")
        self.assertFalse(invalid_pid["cli_validation"]["valid"])
        self.assertEqual(invalid_pid["cli_validation"]["code"], "INVALID_ARGUMENT")

    def test_level3_existing_mapping_remains_compatible(self):
        chmod = map_actions(validate_command("chmod u+s /tmp/rootsh"))
        mount = map_actions(validate_command("mount --bind / /host"))
        self.assertEqual(chmod["actions"][0]["action"], "CHANGE_FILE_PERMISSION")
        self.assertEqual(mount["actions"][0]["action"], "MOUNT_FILESYSTEM")

    def test_seven_commands_are_declarative_full_support(self):
        path = (
            Path(__file__).parents[1]
            / "src/purplebpf/offensive/validator/levels/level2/rules/cli_metadata.json"
        )
        commands = json.loads(path.read_text(encoding="utf-8"))["commands"]
        expected = {
            "cat",
            "chmod",
            "unshare",
            "nsenter",
            "mount",
            "curl",
            "kill",
        }
        self.assertEqual(
            {name for name in commands if resolve_support_tier(name) == "full"},
            expected,
        )


if __name__ == "__main__":
    unittest.main()
