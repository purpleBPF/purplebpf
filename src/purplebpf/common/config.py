"""공용 설정/커넥션 헬퍼. 접속 정보는 레포 루트의 .env에서 읽는다."""
from __future__ import annotations

import os
from urllib.parse import urlparse

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase
from sqlalchemy import Engine, create_engine

_env_file = os.environ.get("PBPF_ENV_FILE")
if _env_file:
    # 명시적으로 지정된 파일만 로드한다. 이미 설정된 값은 덮어쓰지 않는다(override=False).
    # 레포 루트가 여러 환경(예: Lima VM)에 동일 경로로 마운트되는 경우, cwd 기준
    # 자동 탐색(load_dotenv())이 그 환경에 맞지 않는 .env를 잘못 끌어올 수 있어
    # PBPF_ENV_FILE로 로드 대상을 명시적으로 통제할 수 있게 한다.
    load_dotenv(dotenv_path=_env_file, override=False)
else:
    load_dotenv(override=False)


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


def get_slack_signing_secret() -> str:
    """Slack이 보낸 인터랙션(버튼 클릭) 요청이 진짜인지 검증할 때 쓰는 서명 비밀키.

    Slack 앱 관리 페이지의 'Basic Information' > 'Signing Secret'에서 확인할 수 있다.
    Slack 앱 관리자에게 받아서 .env의 SLACK_SIGNING_SECRET에 채워 넣는다.
    """
    secret = os.environ.get("SLACK_SIGNING_SECRET")
    if not secret:
        raise RuntimeError("SLACK_SIGNING_SECRET 환경변수가 설정되어 있지 않다.")
    return secret


def build_db_engine() -> Engine:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL 환경변수가 설정되어 있지 않다.")
    return create_engine(database_url)


def build_postgres_libpq_dsn() -> str:
    """DATABASE_URL을 직접 파싱해 libpq 형식 DSN을 만든다.

    SQLAlchemy의 Engine.url을 str()로 찍으면 비밀번호가 '***'로 마스킹되므로
    (DuckDB의 postgres ATTACH 등 실제 인증이 필요한 곳에 쓰면 인증 실패),
    os.environ에서 DATABASE_URL을 직접 읽어 마스킹을 우회한다.
    """
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL 환경변수가 설정되어 있지 않다.")

    parsed = urlparse(database_url)
    parts = {
        "host": parsed.hostname,
        "port": parsed.port,
        "dbname": (parsed.path or "").lstrip("/"),
        "user": parsed.username,
        "password": parsed.password,
    }
    return " ".join(f"{key}={_quote_libpq_value(str(value))}" for key, value in parts.items() if value)


def _quote_libpq_value(value: str) -> str:
    if " " not in value and '"' not in value:
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
