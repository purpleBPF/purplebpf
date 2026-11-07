"""ATT&CK graph ingestion regression tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from purplebpf.offensive.kg import load_graph


class Neo4jSchemaTests(unittest.TestCase):
    def test_schema_applies_both_constraints_even_with_comments(self):
        with TemporaryDirectory() as tmp:
            schema = Path(tmp) / "schema.cypher"
            schema.write_text(
                "// header\n"
                "CREATE CONSTRAINT technique_id_unique IF NOT EXISTS "
                "FOR (t:Technique) REQUIRE t.id IS UNIQUE;\n"
                "// another comment\n"
                "CREATE CONSTRAINT tactic_id_unique IF NOT EXISTS "
                "FOR (t:Tactic) REQUIRE t.id IS UNIQUE;\n",
                encoding="utf-8",
            )
            driver = Mock()
            session = driver.session.return_value.__enter__.return_value
            with patch.object(load_graph, "SCHEMA_PATH", schema):
                load_graph.apply_schema(driver)

        statements = [call.args[0] for call in session.run.call_args_list]
        self.assertEqual(len(statements), 2)
        self.assertIn("technique_id_unique", statements[0])
        self.assertIn("tactic_id_unique", statements[1])
        self.assertEqual(session.run.return_value.consume.call_count, 2)

    def test_extract_techniques_skips_revoked_entries(self):
        objects = [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--example",
                "name": "Example",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1611"}
                ],
            },
            {
                "type": "attack-pattern",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
            },
        ]
        techniques = load_graph.extract_techniques(objects)
        self.assertEqual([t["id"] for t in techniques], ["T1611"])


if __name__ == "__main__":
    unittest.main()
