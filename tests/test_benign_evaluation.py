import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from purplebpf.offensive.validator.evaluation import evaluate_benign


def validation_result(status, *, stopped_at=None, reason=None, code=None):
    level1 = {"status": "PASS", "steps": []}
    level2 = {"status": "PASS", "errors": []}
    level3 = {"status": "PASS", "errors": []}
    if status == "REVIEW":
        level2 = {"status": "REVIEW", "errors": [{"code": code or "UNSUPPORTED_COMMAND", "message": "review"}]}
        level3 = {"status": "REVIEW", "errors": [{"code": "UNMAPPED_ACTION", "message": "unmapped"}]}
    elif stopped_at == "level1":
        level1 = {
            "status": "FAIL",
            "steps": [{"diagnostic_items": [{"code": 2046, "message": "quote it"}]}],
        }
        level2 = None
        level3 = None
    elif stopped_at == "level2":
        level2 = {"status": "REJECT", "errors": [{"code": code or "INVALID_OPTION", "message": "invalid"}]}
        level3 = None
    elif status == "REJECT":
        level3 = {"status": "REJECT", "errors": [{"code": code or "TECHNIQUE_ACTION_MISMATCH", "message": "mismatch"}]}
    return {
        "level1": level1,
        "level2": level2,
        "level3": level3,
        "final": {"status": status, "stopped_at": stopped_at, "reason": reason},
    }


class BenignEvaluationTests(unittest.TestCase):
    def test_fixed_dataset_loads_all_24_cases(self):
        dataset = evaluate_benign.load_dataset()

        self.assertEqual(len(dataset), 24)
        self.assertEqual(
            [item["file"] for item in dataset],
            list(evaluate_benign.SCENARIO_FILES),
        )
        self.assertTrue(
            all(item["scenario"].get("technique_id") for item in dataset)
        )

    def test_summary_categories_techniques_and_benign_pass_count(self):
        def fake_validator(scenario):
            label = scenario["label"]
            if label == "socket_named_file_access":
                return validation_result("REJECT", code="TECHNIQUE_ACTION_MISMATCH")
            if label in {"tmp_read_only", "tmp_write_no_exec", "worker_drain_on_sigint"}:
                return validation_result(
                    "REJECT",
                    stopped_at="level2",
                    reason="LEVEL2_REJECT",
                    code="INVALID_OPTION",
                )
            if label == "graceful_shutdown_sigterm":
                return validation_result(
                    "REJECT",
                    stopped_at="level1",
                    reason="LEVEL1_SYNTAX_FAILURE",
                )
            if label == "chmod_plain_permissions":
                return validation_result("PASS", reason="LEVEL3_CORE_MATCH")
            return validation_result("REVIEW", reason="LEVEL2_REVIEW")

        result = evaluate_benign.evaluate_dataset(validator=fake_validator)
        summary = result["summary"]

        self.assertEqual(summary["total"], 24)
        self.assertEqual(summary["pass"] + summary["review"] + summary["reject"], 24)
        self.assertEqual(summary["pass"], 1)
        self.assertEqual(summary["review"], 18)
        self.assertEqual(summary["reject"], 5)
        self.assertEqual(summary["semantic_reject"], 1)
        self.assertEqual(summary["level2_coverage_reject"], 3)
        self.assertEqual(summary["level1_reject"], 1)
        self.assertEqual(summary["benign_pass_count"], 1)
        self.assertEqual(summary["benign_pass_rate"], 1 / 24)
        self.assertEqual(
            sum(item["total"] for item in result["technique_summary"].values()),
            24,
        )
        self.assertEqual(result["technique_summary"]["T1610"]["reject"], 1)

        graceful = next(
            case for case in result["cases"]
            if case["file"] == "graceful_shutdown_sigterm.json"
        )
        self.assertEqual(graceful["category"], "level1_reject")
        self.assertIn("SC2046", graceful["error_codes"])

    def test_no_write_does_not_create_output(self):
        result = {"summary": {"total": 24}, "technique_summary": {}, "cases": []}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "benign.json"
            with patch.object(
                evaluate_benign, "evaluate_dataset", return_value=result
            ), patch("builtins.print"):
                exit_code = evaluate_benign.main(
                    ["--no-write", "--output", str(output)]
                )

            self.assertEqual(exit_code, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
