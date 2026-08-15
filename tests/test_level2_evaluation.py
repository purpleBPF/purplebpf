import json
import unittest
from pathlib import Path

from purplebpf.offensive.validator.levels.level2.evaluation.comparator import (
    compare_case,
)
from purplebpf.offensive.validator.levels.level2.evaluation.evaluate import (
    DEFAULT_DATASET,
    evaluate_dataset,
)
from purplebpf.offensive.validator.levels.level2.evaluation.metrics import PRFCounts


class MetricTests(unittest.TestCase):
    def test_prf_counts_are_micro_averaged(self):
        result = PRFCounts(tp=8, fp=2, fn=4).result()

        self.assertEqual(result["precision"], 0.8)
        self.assertEqual(result["recall"], 8 / 12)
        self.assertAlmostEqual(result["f1"], 8 / 11)


class ComparatorTests(unittest.TestCase):
    def test_resource_role_and_element_identity_are_compared(self):
        testcase = {
            "id": "SYNTHETIC-001",
            "expected": {
                "commands": [
                    {
                        "executable": "demo",
                        "tier": "FULL",
                        "cli_valid": True,
                        "elements": [
                            {"raw": "-o", "type": "option"},
                            {
                                "raw": "/tmp/a",
                                "type": "option_value",
                                "option": "-o",
                            },
                        ],
                        "resources": {
                            "requires": [],
                            "produces": [
                                {"type": "file", "identity": {"path": "/tmp/a"}}
                            ],
                        },
                        "facts": [],
                    }
                ]
            },
        }
        actual = {
            "commands": [
                {
                    "executable": {"raw": "demo", "normalized": "demo"},
                    "support_tier": "full",
                    "cli_validation": {"valid": True, "code": None},
                    "elements": [
                        {"raw": "-o", "type": "option"},
                        {
                            "raw": "/tmp/a",
                            "type": "option_value",
                            "option": "-o",
                        },
                    ],
                    "resources": {
                        "requires": [
                            {"type": "file", "identity": {"path": "/tmp/a"}}
                        ],
                        "produces": [],
                    },
                    "facts": [],
                }
            ]
        }

        comparison = compare_case(testcase, actual)

        self.assertEqual(comparison["argument_mapping"].result()["f1"], 1.0)
        self.assertEqual(comparison["resource"].tp, 0)
        self.assertEqual(comparison["resource"].fp, 1)
        self.assertEqual(comparison["resource"].fn, 1)


class GroundTruthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = json.loads(Path(DEFAULT_DATASET).read_text(encoding="utf-8"))

    def test_dataset_has_requested_distribution_and_unique_ids(self):
        cases = self.dataset["cases"]
        categories = {
            name: sum(case["category"] == name for case in cases)
            for name in ("tier1", "tier2", "composition")
        }
        subjects = {
            name: sum(case["subject"] == name for case in cases)
            for name in (
                "chmod",
                "unshare",
                "nsenter",
                "mount",
                "curl",
                "kill",
                "wget",
                "cat",
                "pkill",
                "grep",
                "tar",
                "composition",
            )
        }

        self.assertEqual(len(cases), 100)
        self.assertEqual(categories, {"tier1": 60, "tier2": 25, "composition": 15})
        self.assertTrue(all(subjects[name] == 10 for name in subjects if name in {
            "chmod", "unshare", "nsenter", "mount", "curl", "kill"
        }))
        self.assertTrue(all(subjects[name] == 5 for name in subjects if name in {
            "wget", "cat", "pkill", "grep", "tar"
        }))
        self.assertEqual(subjects["composition"], 15)
        identifiers = [case["id"] for case in cases]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_evaluation_produces_all_requested_metrics_and_failures(self):
        result = evaluate_dataset()

        self.assertEqual(result["total_cases"], 100)
        for name in (
            "command_extraction",
            "cli_validation",
            "argument_mapping",
            "resource",
            "fact",
            "tier",
        ):
            self.assertIn(name, result)
        self.assertIn("confusion_matrix", result["tier"])
        self.assertIn("confusion_matrix", result["cli_validation"])
        self.assertIn("false_invalid", result["cli_validation"])
        self.assertIn("false_valid", result["cli_validation"])
        self.assertEqual(
            result["failed_case_count"],
            len({failure["id"] for failure in result["failures"]}),
        )
        self.assertTrue(all("id" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main()
