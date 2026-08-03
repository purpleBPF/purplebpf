"""MITRE ATT&CK STIX 번들을 Neo4j에 Technique/Tactic 그래프로 적재한다.

CTI 리포트 기반 ENABLES 관계는 이 스크립트의 스코프에 포함하지 않는다 (다음 단계).

검증 쿼리 예시:
    MATCH (t:Technique) WHERE t.id IN ['T1611', 'T1548'] RETURN t.id, t.name, t.platforms
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib

from neo4j import GraphDatabase

STIX_PATH = pathlib.Path("data/stix/enterprise-attack.json")
SCHEMA_PATH = pathlib.Path(__file__).parent / "schema.cypher"

MITRE_SOURCE = "mitre-attack"


def _get_ref_field(stix_obj: dict, field: str) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == MITRE_SOURCE:
            return ref.get(field)
    return None


def load_stix_objects(path: pathlib.Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        bundle = json.load(f)
    return bundle["objects"]


def extract_tactics(objects: list[dict]) -> list[dict]:
    tactics = []
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        attack_id = _get_ref_field(obj, "external_id")
        if not attack_id:
            continue
        tactics.append(
            {
                "id": attack_id,
                "name": obj.get("name"),
                "shortname": obj.get("x_mitre_shortname"),
            }
        )
    return tactics


def extract_techniques(objects: list[dict]) -> list[dict]:
    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_id = _get_ref_field(obj, "external_id")
        if not attack_id:
            continue
        kill_chain_phases = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == MITRE_SOURCE
        ]
        techniques.append(
            {
                "stix_id": obj.get("id"),
                "id": attack_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "url": _get_ref_field(obj, "url"),
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "kill_chain_phases": kill_chain_phases,
            }
        )
    return techniques


def extract_subtechnique_relationships(objects: list[dict]) -> list[dict]:
    relationships = []
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "subtechnique-of":
            continue
        if obj.get("revoked"):
            continue
        relationships.append(
            {
                "source_ref": obj.get("source_ref"),
                "target_ref": obj.get("target_ref"),
            }
        )
    return relationships


def build_neo4j_driver():
    uri = os.environ.get("NEO4J_URI")
    auth_raw = os.environ.get("NEO4J_AUTH")
    if not uri:
        raise RuntimeError("NEO4J_URI 환경변수가 설정되어 있지 않다.")
    if not auth_raw:
        raise RuntimeError("NEO4J_AUTH 환경변수가 설정되어 있지 않다.")

    username, _, password = auth_raw.partition("/")
    if not username or not password:
        raise RuntimeError("NEO4J_AUTH는 'neo4j/비밀번호' 형식이어야 한다.")

    return GraphDatabase.driver(uri, auth=(username, password))


def apply_schema(driver) -> None:
    statements = [
        stmt.strip()
        for stmt in SCHEMA_PATH.read_text(encoding="utf-8").split(";")
        if stmt.strip() and not stmt.strip().startswith("//")
    ]
    with driver.session() as session:
        for stmt in statements:
            session.run(stmt)


def load_tactics(driver, tactics: list[dict]) -> None:
    query = """
    UNWIND $tactics AS tactic
    MERGE (t:Tactic {id: tactic.id})
    SET t.name = tactic.name,
        t.shortname = tactic.shortname
    """
    with driver.session() as session:
        session.run(query, tactics=tactics)


def load_techniques(driver, techniques: list[dict]) -> None:
    query = """
    UNWIND $techniques AS tech
    MERGE (t:Technique {id: tech.id})
    SET t.name = tech.name,
        t.description = tech.description,
        t.url = tech.url,
        t.platforms = tech.platforms,
        t.is_subtechnique = tech.is_subtechnique
    """
    with driver.session() as session:
        session.run(query, techniques=techniques)


def load_belongs_to(driver, techniques: list[dict]) -> int:
    pairs = [
        {"technique_id": tech["id"], "tactic_shortname": phase}
        for tech in techniques
        for phase in tech["kill_chain_phases"]
    ]
    query = """
    UNWIND $pairs AS pair
    MATCH (tech:Technique {id: pair.technique_id})
    MATCH (tac:Tactic {shortname: pair.tactic_shortname})
    MERGE (tech)-[:BELONGS_TO]->(tac)
    """
    with driver.session() as session:
        session.run(query, pairs=pairs)
    return len(pairs)


def load_subtechnique_of(driver, techniques: list[dict], relationships: list[dict]) -> int:
    stix_id_to_attack_id = {tech["stix_id"]: tech["id"] for tech in techniques}
    pairs = []
    for rel in relationships:
        child_id = stix_id_to_attack_id.get(rel["source_ref"])
        parent_id = stix_id_to_attack_id.get(rel["target_ref"])
        if child_id and parent_id:
            pairs.append({"child": child_id, "parent": parent_id})

    query = """
    UNWIND $pairs AS pair
    MATCH (child:Technique {id: pair.child})
    MATCH (parent:Technique {id: pair.parent})
    MERGE (child)-[:SUBTECHNIQUE_OF]->(parent)
    """
    with driver.session() as session:
        session.run(query, pairs=pairs)
    return len(pairs)


def print_graph_counts(driver) -> None:
    counts_queries = {
        "Technique": "MATCH (t:Technique) RETURN count(t) AS c",
        "Tactic": "MATCH (t:Tactic) RETURN count(t) AS c",
        "BELONGS_TO": "MATCH ()-[r:BELONGS_TO]->() RETURN count(r) AS c",
        "SUBTECHNIQUE_OF": "MATCH ()-[r:SUBTECHNIQUE_OF]->() RETURN count(r) AS c",
    }
    with driver.session() as session:
        for label, query in counts_queries.items():
            count = session.run(query).single()["c"]
            print(f"{label}: {count}건")


def main() -> None:
    parser = argparse.ArgumentParser(description="ATT&CK STIX 번들을 Neo4j에 적재한다")
    parser.add_argument(
        "--stix-path",
        type=pathlib.Path,
        default=STIX_PATH,
        help="적재할 STIX JSON 번들 경로 (기본: data/stix/enterprise-attack.json)",
    )
    args = parser.parse_args()

    if not args.stix_path.exists():
        raise FileNotFoundError(
            f"{args.stix_path} 파일이 없다. download_stix.py를 먼저 실행한다."
        )

    objects = load_stix_objects(args.stix_path)
    tactics = extract_tactics(objects)
    techniques = extract_techniques(objects)
    subtechnique_relationships = extract_subtechnique_relationships(objects)

    driver = build_neo4j_driver()
    try:
        apply_schema(driver)
        load_tactics(driver, tactics)
        load_techniques(driver, techniques)
        belongs_to_count = load_belongs_to(driver, techniques)
        subtechnique_of_count = load_subtechnique_of(
            driver, techniques, subtechnique_relationships
        )

        print(f"Tactic {len(tactics)}건, Technique {len(techniques)}건 적재 완료")
        print(
            f"BELONGS_TO {belongs_to_count}건, "
            f"SUBTECHNIQUE_OF {subtechnique_of_count}건 관계 생성 완료"
        )
        print_graph_counts(driver)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
