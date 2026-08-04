"""공용 설정/커넥션 헬퍼. 접속 정보는 레포 루트의 .env에서 읽는다."""
from __future__ import annotations

import os

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase

load_dotenv()


def build_neo4j_driver() -> Driver:
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


def get_ollama_host() -> str:
    return os.environ.get("OLLAMA_HOST", "http://localhost:11434")


def get_gemma_model() -> str:
    return os.environ.get("GEMMA_MODEL", "gemma2:2b")


def get_slack_webhook_url() -> str:
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        raise RuntimeError("SLACK_WEBHOOK_URL 환경변수가 설정되어 있지 않다.")
    return url
