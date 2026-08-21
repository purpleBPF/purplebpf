import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from purplebpf.offensive.validator.levels.level2.parser.metadata_provider import JsonMetadataProvider
from purplebpf.offensive.validator.levels.level2.support_tier import resolve_support_tier
from purplebpf.offensive.validator.levels.level2.tools.metadata_generator import (
    extract_options,
    generate_candidate,
)
from purplebpf.offensive.validator.levels.level2.validator import validate_shell
from purplebpf.offensive.validator.levels.level3.mapper import map_actions


class MetadataGeneratorTests(unittest.TestCase):
    def test_extracts_aliases_required_and_optional_values(self):
        options = extract_options(
            """
  -q, --quiet                 suppress output
  -o, --output=FILE           write FILE
      --color[=WHEN]          color output
  -f FILE, --file FILE        read FILE
"""
        )

        self.assertEqual(options[0], {"names": ["-q", "--quiet"]})
        self.assertEqual(options[1]["names"], ["-o", "--output"])
        self.assertEqual(options[1]["value"], "required")
        self.assertEqual(options[1]["value_name"], "FILE")
        self.assertEqual(options[2]["value"], "optional_attached")
        self.assertEqual(options[3]["value"], "required")

    def test_five_local_candidates_use_help_and_remain_pending(self):
        for command in ("wget", "cat", "pkill", "grep", "tar"):
            if shutil.which(command) is None:
                self.skipTest(f"{command} is not installed")
            with self.subTest(command=command):
                candidate = generate_candidate(command)
                self.assertTrue(candidate["generated"])
                self.assertEqual(candidate["source"]["type"], "help")
                self.assertEqual(candidate["review_status"], "PENDING")
                self.assertTrue(candidate["metadata"]["options"])
                self.assertTrue(candidate["provenance"]["generated_at"])

    def test_help_is_preferred_and_man_is_only_a_fallback(self):
        help_without_options = unittest.mock.Mock(
            stdout="Usage: demo\n", stderr="", returncode=0
        )
        man_with_options = unittest.mock.Mock(
            stdout="  -h, --help  display help\n", stderr="", returncode=0
        )
        version = unittest.mock.Mock(
            stdout="demo 1.0\n", stderr="", returncode=0
        )
        with patch(
            "purplebpf.offensive.validator.levels.level2.tools.metadata_generator.shutil.which",
            return_value="/usr/bin/demo",
        ), patch(
            "purplebpf.offensive.validator.levels.level2.tools.metadata_generator._run_documentation",
            side_effect=[help_without_options, man_with_options, version],
        ):
            candidate = generate_candidate("demo")

        self.assertEqual(candidate["source"]["type"], "man")

    def test_missing_command_is_generation_failure_not_validation_error(self):
        with patch(
            "purplebpf.offensive.validator.levels.level2.tools.metadata_generator.shutil.which", return_value=None
        ):
            candidate = generate_candidate("not-installed-here")

        self.assertFalse(candidate["generated"])
        self.assertEqual(candidate["code"], "LOCAL_COMMAND_NOT_FOUND")

    def test_output_directory_is_not_a_runtime_metadata_source(self):
        with tempfile.TemporaryDirectory() as directory:
            pending = Path(directory) / "pending.json"
            pending.write_text(
                json.dumps(
                    {
                        "command": "pending-only-command",
                        "review_status": "PENDING",
                        "metadata": {"operands": {}, "options": []},
                    }
                ),
                encoding="utf-8",
            )
            runtime = JsonMetadataProvider()

        self.assertIsNone(runtime.get("pending-only-command"))

    def test_runtime_provider_skips_pending_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cli_metadata.json"
            path.write_text(
                json.dumps(
                    {
                        "commands": {
                            "pending-command": {
                                "provenance": {"review_status": "PENDING"},
                                "operands": {},
                                "options": [],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            runtime = JsonMetadataProvider(path)
            result = runtime.get("pending-command")

        self.assertIsNone(result)


class ApprovedMetadataTests(unittest.TestCase):
    def test_approved_commands_keep_expected_support_tiers(self):
        for command in ("wget", "pkill", "grep", "tar"):
            with self.subTest(command=command):
                self.assertEqual(resolve_support_tier(command), "metadata")
        self.assertEqual(resolve_support_tier("cat"), "full")

    def test_requested_approved_invocations(self):
        commands = [
            "wget https://example.com/a",
            "wget -O /tmp/a https://example.com/a",
            "cat /tmp/a",
            "cat -n /tmp/a",
            "pkill tetragon",
            "pkill -9 tetragon",
            "grep token /tmp/a",
            "grep -r token /tmp",
            "tar -xzf payload.tar.gz",
            "tar -xzf payload.tar.gz -C /tmp",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = validate_shell(command)["commands"][0]
                expected_tier = "full" if command.startswith("cat ") else "metadata"
                self.assertEqual(result["support_tier"], expected_tier)
                self.assertTrue(result["cli_validation"]["valid"])
                self.assertEqual(result["resources"], {"requires": [], "produces": []})
                if command.startswith("cat "):
                    self.assertEqual(result["facts"][0]["type"], "file_access")
                else:
                    self.assertEqual(result["facts"], [])

    def test_wget_invalid_option_is_rejected(self):
        result = validate_shell(
            "wget --definitely-invalid-option https://example.com"
        )["commands"][0]

        self.assertFalse(result["cli_validation"]["valid"])
        self.assertEqual(result["cli_validation"]["code"], "INVALID_OPTION")

    def test_tar_cluster_is_expanded_and_value_is_bound_to_file(self):
        result = validate_shell("tar -xzf payload.tar.gz -C /tmp")["commands"][0]

        self.assertEqual(
            result["elements"],
            [
                {"raw": "-x", "type": "option"},
                {"raw": "-z", "type": "option"},
                {"raw": "-f", "type": "option"},
                {"raw": "payload.tar.gz", "type": "option_value", "option": "-f"},
                {"raw": "-C", "type": "option"},
                {"raw": "/tmp", "type": "option_value", "option": "-C"},
            ],
        )

    def test_full_metadata_generic_are_inferred_from_available_layers(self):
        self.assertEqual(resolve_support_tier("mount"), "full")
        self.assertEqual(resolve_support_tier("wget"), "metadata")
        self.assertEqual(resolve_support_tier("socat"), "generic")

    def test_level3_does_not_map_tier2_without_evidence(self):
        invocation = validate_shell("grep token /tmp/a")["commands"][0]
        mapped = map_actions(invocation)

        self.assertEqual(invocation["support_tier"], "metadata")
        self.assertFalse(mapped["action_validation"]["mapped"])


if __name__ == "__main__":
    unittest.main()
