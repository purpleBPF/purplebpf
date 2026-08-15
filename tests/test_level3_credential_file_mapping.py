import unittest

from levels.level2.engine import JsonCredentialTargetClassifier
from levels.level2.validator import validate_command
from levels.level3.mapper import map_actions
from levels.level3.validator import validate_scenario as validate_level3


class CredentialTargetClassifierTests(unittest.TestCase):
    def setUp(self):
        self.classifier = JsonCredentialTargetClassifier()

    def test_high_confidence_targets_are_classified(self):
        targets = {
            "/home/alice/.aws/credentials": "aws_credentials",
            "~/.kube/config": "kubeconfig",
            "/var/run/secrets/kubernetes.io/serviceaccount/token": (
                "service_account_token"
            ),
            "/home/alice/.ssh/id_rsa": "ssh_private_key",
            "/home/alice/.ssh/id_ed25519": "ssh_private_key",
        }
        for path, expected_type in targets.items():
            with self.subTest(path=path):
                result = self.classifier.classify(path)
                self.assertTrue(result["classified"])
                self.assertEqual(result["data_type"], "credential")
                self.assertEqual(result["credential_type"], expected_type)
                self.assertTrue(result["rule_id"].startswith("credential-"))

    def test_keywords_and_nearby_paths_are_not_classified(self):
        paths = (
            "/tmp/config",
            "./settings.json",
            "/etc/example.conf",
            "/tmp/password-test.txt",
            "/tmp/credentials.txt",
            "/home/alice/.ssh/config",
            "/home/alice/.ssh/id_rsa.pub",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertFalse(self.classifier.classify(path)["classified"])

    def test_normalization_is_lexical_only(self):
        result = self.classifier.classify(
            "/home/alice/tmp/../.aws/credentials"
        )

        self.assertTrue(result["classified"])
        self.assertEqual(result["normalized_path"], "/home/alice/.aws/credentials")
        self.assertEqual(
            self.classifier.normalize("~/.aws/credentials"),
            "~/.aws/credentials",
        )


class CredentialReadFactTests(unittest.TestCase):
    def test_general_cat_creates_unclassified_read_fact_and_action(self):
        level2 = validate_command("cat /tmp/a")
        fact = level2["facts"][0]
        action = map_actions(level2)["actions"][0]

        self.assertEqual(fact["type"], "file_access")
        self.assertEqual(fact["identity"], {"path": "/tmp/a"})
        self.assertEqual(
            fact["attributes"],
            {"operation": "read", "path_type": "temporary"},
        )
        self.assertEqual(action["action"], "READ_FILE")
        self.assertEqual(action["context"], {"path_type": "temporary"})

    def test_credential_classification_enriches_read_fact(self):
        level2 = validate_command("cat /home/alice/.aws/credentials")
        fact = level2["facts"][0]
        action = map_actions(level2)["actions"][0]

        self.assertEqual(fact["attributes"]["operation"], "read")
        self.assertEqual(fact["attributes"]["data_type"], "credential")
        self.assertEqual(
            fact["attributes"]["credential_type"], "aws_credentials"
        )
        self.assertEqual(
            fact["evidence"]["classification_rule"],
            "credential-aws-credentials",
        )
        self.assertEqual(
            action["context"],
            {
                "data_type": "credential",
                "credential_type": "aws_credentials",
            },
        )
        self.assertEqual(action["evidence"]["source_fact"], fact)
        self.assertEqual(action["evidence"]["path"], "/home/alice/.aws/credentials")

    def test_cat_stdin_does_not_create_file_read(self):
        level2 = validate_command("cat -")

        self.assertEqual(level2["facts"], [])
        self.assertFalse(map_actions(level2)["action_validation"]["mapped"])


class CredentialReadTechniqueEndToEndTests(unittest.TestCase):
    def _validate(self, command):
        return validate_level3(
            {
                "technique_id": "T1552.001",
                "steps": [{"order": 1, "command": command}],
            }
        )

    def _assert_positive(self, command, credential_type):
        result = self._validate(command)

        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["technique_validation"]["matched"])
        action = result["steps"][0]["actions"][0]
        self.assertEqual(action["action"], "READ_FILE")
        self.assertEqual(action["context"]["data_type"], "credential")
        self.assertEqual(action["context"]["credential_type"], credential_type)
        self.assertIn("classification_rule", action["evidence"])

    def test_aws_credentials_matches(self):
        self._assert_positive(
            "cat /home/alice/.aws/credentials", "aws_credentials"
        )

    def test_kubeconfig_matches(self):
        self._assert_positive("cat /home/alice/.kube/config", "kubeconfig")

    def test_service_account_token_matches(self):
        self._assert_positive(
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            "service_account_token",
        )

    def test_ssh_private_key_matches(self):
        self._assert_positive(
            "cat /home/alice/.ssh/id_rsa", "ssh_private_key"
        )

    def test_general_file_read_does_not_match(self):
        result = self._validate("cat /tmp/example.txt")

        self.assertNotEqual(result["status"], "PASS")
        self.assertIsNot(result["technique_validation"]["matched"], True)
        action = result["steps"][0]["actions"][0]
        self.assertEqual(action["action"], "READ_FILE")
        self.assertNotIn("data_type", action["context"])

    def test_credential_keyword_alone_does_not_match(self):
        result = self._validate("cat /tmp/credentials.txt")

        self.assertNotEqual(result["status"], "PASS")
        action = result["steps"][0]["actions"][0]
        self.assertNotIn("data_type", action["context"])

    def test_credential_target_without_read_does_not_create_read_action(self):
        result = self._validate("touch /home/alice/.aws/credentials")

        self.assertNotEqual(result["status"], "PASS")
        self.assertFalse(
            any(
                action["action"] == "READ_FILE"
                for action in result["steps"][0]["actions"]
            )
        )


if __name__ == "__main__":
    unittest.main()
