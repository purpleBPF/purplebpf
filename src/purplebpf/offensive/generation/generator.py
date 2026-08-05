"""GraphRAG의 생성(generation) 단계 — gemma(Ollama)를 호출해 공격 체인을 생성한다.

이 모듈은 생성만 담당하며, 생성된 체인의 실행(subprocess, docker 등)은 절대 포함하지 않는다.
실행은 별도의 격리된 Executor에서만 이루어진다.
"""
from __future__ import annotations

import argparse
import json

import requests

from purplebpf.common.config import get_gemma_model, get_ollama_host
from purplebpf.offensive.generation.prompt import build_prompt
from purplebpf.offensive.generation.retriever import retrieve_subgraph

REQUEST_TIMEOUT_SECONDS = 120


class ChainGenerationError(Exception):
    """gemma 응답을 유효한 공격 체인 JSON으로 파싱하지 못했을 때 발생한다."""


def generate_chain(technique_id: str) -> dict:
    subgraph = retrieve_subgraph(technique_id)
    prompt = build_prompt(subgraph)

    response = requests.post(
        f"{get_ollama_host()}/api/generate",
        json={
            "model": get_gemma_model(),
            "prompt": prompt,
            "format": "json",
            "stream": False,
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()

    raw_output = response.json().get("response", "")
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise ChainGenerationError(
            f"gemma 응답을 JSON으로 파싱하지 못했다. 원본 응답:\n{raw_output}"
        ) from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="목표 Technique에 대한 공격 체인을 gemma로 생성한다"
    )
    parser.add_argument(
        "technique_id",
        nargs="?",
        default="T1611",
        help="생성할 목표 Technique ID (기본: T1611)",
    )
    args = parser.parse_args()

    chain = generate_chain(args.technique_id)
    print(json.dumps(chain, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
