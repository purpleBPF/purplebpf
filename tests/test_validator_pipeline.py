import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from purplebpf.offensive.validator import main as pipeline


PASSING_SCENARIO = {
    "technique_id": "T1552.005",
    "steps": [
        {
            "order": 1,
            "command": (
                "curl http://169.254.169.254/latest/meta-data/"
            ),
        }
    ],
}


def _level1(passed=True):
    return {
        "passed": passed,
        "exit_code": 0 if passed else 1,
        "diagnostics": "" if passed else "syntax error",
    }


class ScenarioPipelineTests(unittest.TestCase):
    def test_level1_failure_stops_before_level2_and_level3(self):
        with patch.object(
            pipeline, "check_shell_syntax", return_value=_level1(False)
        ), patch.object(pipeline, "validate_level2") as level2, patch.object(
            pipeline, "validate_level3"
        ) as level3:
            result = pipeline.validate_scenario_pipeline(PASSING_SCENARIO)

        self.assertEqual(result["final"], {
            "status": "REJECT",
            "stopped_at": "level1",
            "reason": "LEVEL1_SYNTAX_FAILURE",
        })
        self.assertIsNone(result["level2"])
        self.assertIsNone(result["level3"])
        level2.assert_not_called()
        level3.assert_not_called()

    def test_level2_reject_stops_before_level3(self):
        level2_result = {
            "level": 2,
            "status": "REJECT",
            "steps": [],
            "errors": [],
            "resource_state": [],
        }
        with patch.object(
            pipeline, "check_shell_syntax", return_value=_level1()
        ), patch.object(
            pipeline, "validate_level2", return_value=level2_result
        ) as level2, patch.object(pipeline, "validate_level3") as level3:
            result = pipeline.validate_scenario_pipeline(PASSING_SCENARIO)

        self.assertEqual(result["final"]["status"], "REJECT")
        self.assertEqual(result["final"]["stopped_at"], "level2")
        self.assertIs(result["level2"], level2_result)
        level2.assert_called_once_with(PASSING_SCENARIO)
        level3.assert_not_called()

    def test_level2_review_is_passed_to_level3_once(self):
        level2_result = {
            "level": 2,
            "status": "REVIEW",
            "steps": [],
            "errors": [],
            "resource_state": [],
        }
        level3_result = {"level": 3, "status": "REVIEW"}
        with patch.object(
            pipeline, "check_shell_syntax", return_value=_level1()
        ), patch.object(
            pipeline, "validate_level2", return_value=level2_result
        ) as level2, patch.object(
            pipeline, "validate_level3", return_value=level3_result
        ) as level3:
            result = pipeline.validate_scenario_pipeline(PASSING_SCENARIO)

        level2.assert_called_once_with(PASSING_SCENARIO)
        level3.assert_called_once_with(
            PASSING_SCENARIO, level2_output=level2_result
        )
        self.assertEqual(result["final"]["status"], "REVIEW")
        self.assertIsNone(result["final"]["stopped_at"])

    def test_level2_review_is_not_overridden_by_level3_pass(self):
        level2_result = {
            "level": 2,
            "status": "REVIEW",
            "steps": [],
            "errors": [{"code": "UNSUPPORTED_COMMAND"}],
            "resource_state": [],
        }
        level3_result = {"level": 3, "status": "PASS"}
        with patch.object(
            pipeline, "check_shell_syntax", return_value=_level1()
        ), patch.object(
            pipeline, "validate_level2", return_value=level2_result
        ), patch.object(
            pipeline, "validate_level3", return_value=level3_result
        ):
            result = pipeline.validate_scenario_pipeline(PASSING_SCENARIO)

        self.assertEqual(result["final"], {
            "status": "REVIEW",
            "stopped_at": None,
            "reason": "LEVEL2_REVIEW",
        })

    def test_validator_exception_is_reported_as_error(self):
        with patch.object(
            pipeline, "check_shell_syntax", return_value=_level1()
        ), patch.object(
            pipeline, "validate_level2", side_effect=RuntimeError("unavailable")
        ):
            result = pipeline.validate_scenario_pipeline(PASSING_SCENARIO)

        self.assertEqual(result["level2"]["status"], "ERROR")
        self.assertEqual(result["final"], {
            "status": "ERROR",
            "stopped_at": "level2",
            "reason": "LEVEL2_ERROR",
        })

    def test_level3_reuses_level2_output_without_fallback_analysis(self):
        level2_result = {
            "level": 2,
            "status": "PASS",
            "steps": [
                {
                    "order": 1,
                    "raw_command": PASSING_SCENARIO["steps"][0]["command"],
                    "executable": {"raw": "curl", "normalized": "curl"},
                    "argv": [],
                    "elements": [],
                    "resources": {"requires": [], "produces": []},
                    "facts": [
                        {
                            "type": "endpoint",
                            "identity": {
                                "url": (
                                    "http://169.254.169.254/latest/meta-data/"
                                )
                            },
                            "attributes": {
                                "protocol": "http",
                                "address": "169.254.169.254",
                                "class": "cloud_metadata",
                            },
                        }
                    ],
                }
            ],
            "errors": [],
            "resource_state": [],
        }
        with patch.object(
            pipeline, "check_shell_syntax", return_value=_level1()
        ), patch.object(
            pipeline, "validate_level2", return_value=level2_result
        ) as level2, patch(
            "purplebpf.offensive.validator.levels.level3.validator."
            "validate_level2_shell",
            side_effect=AssertionError("Level 2 fallback must not run"),
        ) as fallback:
            result = pipeline.validate_scenario_pipeline(PASSING_SCENARIO)

        level2.assert_called_once_with(PASSING_SCENARIO)
        fallback.assert_not_called()
        self.assertEqual(result["level3"]["status"], "PASS")
        self.assertEqual(result["final"]["status"], "PASS")


class ValidationStatusAggregationTests(unittest.TestCase):
    @staticmethod
    def level(status):
        return {"status": status}

    def test_supported_status_combinations(self):
        cases = (
            ("PASS", "PASS", "PASS", "PASS"),
            ("PASS", "REVIEW", "PASS", "REVIEW"),
            ("PASS", "PASS", "REVIEW", "REVIEW"),
            ("PASS", "REVIEW", "REVIEW", "REVIEW"),
            ("PASS", "PASS", "REJECT", "REJECT"),
        )
        for level1, level2, level3, expected in cases:
            with self.subTest(level1=level1, level2=level2, level3=level3):
                final = pipeline.aggregate_validation_status(
                    self.level(level1), self.level(level2), self.level(level3)
                )
                self.assertEqual(final["status"], expected)

    def test_valid_early_stops_are_not_missing_result_errors(self):
        level1_reject = pipeline.aggregate_validation_status(
            self.level("FAIL"), None, None
        )
        level2_reject = pipeline.aggregate_validation_status(
            self.level("PASS"), self.level("REJECT"), None
        )

        self.assertEqual(level1_reject["status"], "REJECT")
        self.assertEqual(level1_reject["stopped_at"], "level1")
        self.assertEqual(level2_reject["status"], "REJECT")
        self.assertEqual(level2_reject["stopped_at"], "level2")

    def test_unknown_or_missing_results_are_errors(self):
        unknown = pipeline.aggregate_validation_status(
            self.level("PASS"), self.level("UNKNOWN"), self.level("PASS")
        )
        missing = pipeline.aggregate_validation_status(
            self.level("PASS"), self.level("PASS"), None
        )

        self.assertEqual(unknown["status"], "ERROR")
        self.assertEqual(missing["status"], "ERROR")


class ScenarioCliTests(unittest.TestCase):
    def test_main_prints_clear_invalid_json_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenario.json"
            path.write_text("{", encoding="utf-8")
            with patch.object(pipeline, "_print_cli_error") as error:
                exit_code = pipeline.main([str(path)])

        self.assertEqual(exit_code, 2)
        error.assert_called_once()
        self.assertEqual(error.call_args.args[0], "INVALID_JSON")

    def test_main_prints_pipeline_json(self):
        expected = {"final": {"status": "PASS"}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenario.json"
            path.write_text(json.dumps(PASSING_SCENARIO), encoding="utf-8")
            with patch.object(
                pipeline, "validate_scenario_pipeline", return_value=expected
            ), patch("builtins.print") as output:
                exit_code = pipeline.main([str(path)])

        self.assertEqual(exit_code, 0)
        rendered = json.loads(output.call_args.args[0])
        self.assertEqual(rendered, expected)


if __name__ == "__main__":
    unittest.main()
