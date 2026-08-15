import unittest

from purplebpf.offensive.validator.levels.level2.validator import validate_shell


def invocation(command):
    return validate_shell(command)["commands"][0]


class LongOptionGrammarTests(unittest.TestCase):
    def test_required_long_option_value_supports_attached_and_separate_forms(self):
        attached = invocation("wget --timeout=5 https://example.com/a")
        separate = invocation("wget --timeout 5 https://example.com/a")
        short = invocation("wget -T 5 https://example.com/a")

        self.assertTrue(attached["cli_validation"]["valid"])
        self.assertTrue(separate["cli_validation"]["valid"])
        self.assertTrue(short["cli_validation"]["valid"])
        self.assertEqual(attached["elements"][0]["raw"], "--timeout")
        self.assertEqual(attached["elements"][1]["raw"], "5")
        self.assertEqual(attached["elements"][1]["option"], "--timeout")

    def test_optional_attached_value_is_mapped(self):
        result = invocation("grep --color=auto token /tmp/a")

        self.assertTrue(result["cli_validation"]["valid"])
        self.assertEqual(
            result["elements"][:2],
            [
                {"raw": "--color", "type": "option"},
                {"raw": "auto", "type": "option_value", "option": "--color"},
            ],
        )

    def test_value_on_flag_remains_invalid(self):
        result = invocation("wget --quiet=yes https://example.com/a")

        self.assertFalse(result["cli_validation"]["valid"])
        self.assertEqual(result["cli_validation"]["code"], "INVALID_OPTION")

    def test_unknown_option_does_not_discard_following_operand(self):
        result = invocation("wget --unknown-option https://example.com/a")

        self.assertFalse(result["cli_validation"]["valid"])
        self.assertEqual(
            result["elements"],
            [
                {
                    "raw": "https://example.com/a",
                    "type": "operand",
                    "position": 1,
                }
            ],
        )

    def test_pkill_uid_keeps_pattern_as_operand(self):
        result = invocation("pkill --uid root nginx")

        self.assertTrue(result["cli_validation"]["valid"])
        self.assertEqual(
            result["elements"],
            [
                {"raw": "--uid", "type": "option"},
                {"raw": "root", "type": "option_value", "option": "--uid"},
                {"raw": "nginx", "type": "operand", "position": 1},
            ],
        )


class SemanticBindingTests(unittest.TestCase):
    def test_curl_url_option_and_operand_produce_same_facts(self):
        positional = invocation("curl https://example.com/a")
        option = invocation("curl --url https://example.com/a")

        self.assertTrue(option["cli_validation"]["valid"])
        self.assertEqual(option["facts"], positional["facts"])

    def test_mount_option_values_fill_source_and_target(self):
        result = invocation("mount --source /dev/sda1 --target /host")

        self.assertTrue(result["cli_validation"]["valid"])
        self.assertEqual(
            result["resources"]["produces"],
            [
                {
                    "type": "mount",
                    "identity": {"source": "/dev/sda1", "target": "/host"},
                }
            ],
        )
        self.assertEqual(
            result["facts"],
            [
                {
                    "type": "mount",
                    "identity": {"source": "/dev/sda1", "target": "/host"},
                    "attributes": {
                        "operation": "mount",
                        "source_type": "device",
                    },
                }
            ],
        )


class DeclarativeValidationTests(unittest.TestCase):
    def test_supported_chmod_modes_remain_valid(self):
        for mode in ("u+s", "g+s", "ug+s", "u-s", "g-s", "+x", "4755", "2755", "0755", "755"):
            with self.subTest(mode=mode):
                self.assertTrue(
                    invocation(f"chmod {mode} /tmp/a")["cli_validation"]["valid"]
                )

    def test_clearly_invalid_chmod_modes_are_invalid_arguments(self):
        for mode in ("u+q", "9999"):
            with self.subTest(mode=mode):
                validation = invocation(f"chmod {mode} /tmp/a")["cli_validation"]
                self.assertFalse(validation["valid"])
                self.assertEqual(validation["code"], "INVALID_ARGUMENT")

    def test_reference_form_does_not_apply_mode_rule_to_target(self):
        result = invocation("chmod --reference=/tmp/ref /tmp/a")

        self.assertTrue(result["cli_validation"]["valid"])

    def test_unknown_kill_signal_is_invalid_option(self):
        result = invocation("kill -FOO 1234")

        self.assertFalse(result["cli_validation"]["valid"])
        self.assertEqual(result["cli_validation"]["code"], "INVALID_OPTION")
        self.assertEqual(
            result["elements"],
            [{"raw": "1234", "type": "operand", "position": 1}],
        )

    def test_real_but_unmodeled_signal_remains_reviewable(self):
        validation = invocation("kill -HUP 1234")["cli_validation"]

        self.assertIsNone(validation["valid"])
        self.assertEqual(validation["code"], "UNMAPPED_ARGUMENT")


if __name__ == "__main__":
    unittest.main()
