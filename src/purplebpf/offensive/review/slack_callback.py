"""[비상용] HTTP Request URL 방식 수신부 — 기본 수신부는 slack_socket.py(Socket Mode)다.

Slack 앱에서 Socket Mode를 켜면 Slack은 Request URL로 요청을 보내지 않는다.
이 모듈은 Socket Mode를 쓸 수 없는 환경(예: 아웃바운드 WebSocket 차단)을 위해
남겨둔 것이다. 이 경우 ngrok 같은 도구로 서버를 외부에 노출하고, 그 주소를
Slack 앱의 'Interactivity & Shortcuts' > Request URL에 등록해야 한다.

처리 흐름:
1. 진짜 Slack이 보낸 요청인지 서명(Signing Secret)을 검증하고
2. payload를 꺼내 decision.handle_block_actions()에 넘긴다
   (판정·중복 처리·메시지 갱신 로직은 Socket Mode 수신부와 같은 코드).

[현재 구현 상태 — 표시 전용(display-only)]
승인(approve_chain)을 눌러도 실제 체인 (재)실행이나 execution_log 갱신은 없다.
"승인 → 실제 실행" 연결은 별도 과제다.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from urllib.parse import parse_qs

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

from purplebpf.common.config import get_slack_signing_secret
from purplebpf.offensive.review.decision import (  # noqa: F401  (기존 import 호환)
    DECISION_LABELS,
    handle_block_actions,
    replace_action_block as _replace_action_block,
)

logger = logging.getLogger(__name__)

app = FastAPI()

MAX_REQUEST_AGE_SECONDS = 60 * 5  # 5분 넘게 지난 요청은 재전송(리플레이) 공격으로 보고 거부한다.


@app.post("/slack/interactions")
async def handle_interaction(
    request: Request,
    background_tasks: BackgroundTasks,
    x_slack_signature: str = Header(None),
    x_slack_request_timestamp: str = Header(None),
) -> dict:
    raw_body = await request.body()
    _verify_slack_signature(
        raw_body=raw_body,
        timestamp=x_slack_request_timestamp,
        signature=x_slack_signature,
    )

    payload = _parse_payload(raw_body)
    action_id = ((payload.get("actions") or [{}])[0]).get("action_id")
    if action_id not in DECISION_LABELS:
        logger.warning("알 수 없는 action_id: %s", action_id)
        raise HTTPException(status_code=400, detail="알 수 없는 action_id")

    # 200(ACK)을 먼저 돌려주고 처리는 응답 후에 한다 — Slack 3초 제한 대응.
    background_tasks.add_task(handle_block_actions, payload)
    return {}


def _verify_slack_signature(*, raw_body: bytes, timestamp: str | None, signature: str | None) -> None:
    if not timestamp or not signature:
        raise HTTPException(status_code=400, detail="Slack 서명 헤더가 없다.")

    if abs(time.time() - int(timestamp)) > MAX_REQUEST_AGE_SECONDS:
        raise HTTPException(status_code=400, detail="요청이 너무 오래됐다 (리플레이 의심).")

    signing_secret = get_slack_signing_secret()
    sig_basestring = f"v0:{timestamp}:{raw_body.decode('utf-8')}"
    expected_signature = "v0=" + hmac.new(
        signing_secret.encode("utf-8"),
        sig_basestring.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=401, detail="Slack 서명 검증 실패.")


def _parse_payload(raw_body: bytes) -> dict:
    # Slack은 application/x-www-form-urlencoded로 보내고, 실제 내용은 payload 필드 안에
    # JSON 문자열로 들어있다.
    form = parse_qs(raw_body.decode("utf-8"))
    payload_values = form.get("payload")
    if not payload_values:
        raise HTTPException(status_code=400, detail="payload 필드가 없다.")
    return json.loads(payload_values[0])


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
