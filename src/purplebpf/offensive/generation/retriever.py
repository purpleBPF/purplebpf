"""GraphRAG의 검색(retrieval) 단계 — 목표 Technique 주변 서브그래프를 Neo4j에서 조회한다.

gemma 호출, 프롬프트 조립, 공격 체인 생성은 이 모듈의 스코프에 포함하지 않는다 (다음 단계).
ENABLES 관계는 아직 KG에 없으므로 검색하지 않는다.
"""
from __future__ import annotations

import argparse
import json

from purplebpf.common.config import build_neo4j_driver


def retrieve_subgraph(technique_id: str) -> dict:
    driver = build_neo4j_driver()
    try:
        with driver.session() as session:
            technique = _fetch_technique(session, technique_id)
            if technique is None:
                raise ValueError(f"존재하지 않는 technique_id: {technique_id}")

            # 같은 Tactic 소속이라는 조건만으로는 플랫폼·방식이 무관한 기법까지 섞여
            # (예: 컨테이너 탈출의 형제로 Windows 기법) gemma 프롬프트를 오염시키므로
            # sibling_techniques 검색은 제거한다. 정교한 관련 기법 검색은 KG에
            # ENABLES(선후관계)가 추가되는 다음 단계에서 다룬다.
            return {
                "technique": technique,
                "tactics": _fetch_tactics(session, technique_id),
                "subtechniques": _fetch_subtechniques(session, technique_id),
                "parent": _fetch_parent(session, technique_id),
            }
    finally:
        driver.close()


def _fetch_technique(session, technique_id: str) -> dict | None:
    query = """
    MATCH (t:Technique {id: $technique_id})
    RETURN t.id AS id, t.name AS name, t.description AS description,
           t.url AS url, t.platforms AS platforms, t.is_subtechnique AS is_subtechnique
    """
    record = session.run(query, technique_id=technique_id).single()
    if record is None:
        return None
    return dict(record)


def _fetch_tactics(session, technique_id: str) -> list[dict]:
    query = """
    MATCH (:Technique {id: $technique_id})-[:BELONGS_TO]->(tac:Tactic)
    RETURN tac.id AS id, tac.name AS name, tac.shortname AS shortname
    """
    return [dict(record) for record in session.run(query, technique_id=technique_id)]


def _fetch_subtechniques(session, technique_id: str) -> list[dict]:
    query = """
    MATCH (sub:Technique)-[:SUBTECHNIQUE_OF]->(:Technique {id: $technique_id})
    RETURN sub.id AS id, sub.name AS name
    """
    return [dict(record) for record in session.run(query, technique_id=technique_id)]


def _fetch_parent(session, technique_id: str) -> dict | None:
    query = """
    MATCH (:Technique {id: $technique_id})-[:SUBTECHNIQUE_OF]->(parent:Technique)
    RETURN parent.id AS id, parent.name AS name
    """
    record = session.run(query, technique_id=technique_id).single()
    if record is None:
        return None
    return dict(record)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="목표 Technique 주변 서브그래프를 Neo4j에서 검색한다"
    )
    parser.add_argument(
        "technique_id",
        nargs="?",
        default="T1611",
        help="검색할 목표 Technique ID (기본: T1611)",
    )
    args = parser.parse_args()

    subgraph = retrieve_subgraph(args.technique_id)
    print(json.dumps(subgraph, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
