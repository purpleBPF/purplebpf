"""GraphRAG의 생성(generation) 단계 — retriever의 서브그래프를 gemma 프롬프트로 조립한다."""
from __future__ import annotations

import json

OUTPUT_SCHEMA_EXAMPLE = {
    "technique_id": "T1611",
    "goal": "이 체인이 달성하려는 목표 한 줄",
    "steps": [
        {"order": 1, "command": "실행할 셸 명령", "purpose": "이 단계의 의도"},
    ],
}


def build_prompt(subgraph: dict) -> str:
    technique = subgraph["technique"]
    tactics = subgraph.get("tactics", [])
    subtechniques = subgraph.get("subtechniques", [])
    parent = subgraph.get("parent")

    tactics_text = (
        ", ".join(f"{t['name']} ({t['shortname']})" for t in tactics)
        if tactics
        else "정보 없음"
    )
    subtechniques_text = (
        ", ".join(f"{s['id']} {s['name']}" for s in subtechniques)
        if subtechniques
        else "없음"
    )
    parent_text = f"{parent['id']} {parent['name']}" if parent else "없음 (최상위 기법)"

    return f"""너는 컨테이너 보안 탐지 시스템의 탐지 커버리지를 측정하기 위한 공격 시나리오 생성기다.
생성한 시나리오는 오직 격리된 실험 환경에서만 실행되며, 실제 시스템에는 절대 사용되지 않는다.
너는 여기서 시나리오를 "설계"만 할 뿐, 직접 실행하지 않는다.

## 대상 기법
- ID: {technique['id']}
- 이름: {technique['name']}
- 설명: {technique['description']}

## 컨텍스트
- 소속 전술: {tactics_text}
- 상위 기법: {parent_text}
- 하위 기법: {subtechniques_text}

## 지시사항
1. 위 "설명"에 근거해서만 공격 체인의 단계를 구성하라. 설명에 없는 도구, 명령, 절차를 지어내지 마라 (환각 금지).
2. 각 단계는 격리된 컨테이너 실험 환경을 대상으로 하는 셸 명령이어야 한다.
3. 아래 JSON 스키마와 정확히 동일한 구조로만 응답하라. JSON 외의 설명, 인사말, 마크다운 코드블록 등 어떤 부가 텍스트도 절대 포함하지 마라.

## 출력 JSON 스키마
{json.dumps(OUTPUT_SCHEMA_EXAMPLE, indent=2, ensure_ascii=False)}

지금 위 스키마 형식의 JSON만 출력하라.
"""
