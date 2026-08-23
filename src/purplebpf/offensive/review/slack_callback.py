"""Slack 2차 검수 메시지의 [승인]/[반려] 버튼 클릭을 수신하는 콜백 서버.

Slack은 버튼이 눌리면 여기 등록된 Request URL로 POST 요청을 보낸다. 이 모듈은
그 요청을 받아서:
1. 진짜 Slack이 보낸 요청인지 서명을 검증하고
2. 어떤 기법(technique_id)에 대해 승인/반려가 눌렸는지 확인하고
3. 원래 Slack 메시지를 "✅ 승인됨" / "❌ 반려됨"으로 바꿔서 응답한다.

로컬(WSL2)에서 이 서버를 띄운 뒤, ngrok 같은 도구로 외부에 노출시키고,
그 ngrok 주소를 Slack 앱 설정의 'Interactivity & Shortcuts' > Request URL에
등록해야 실제로 Slack이 요청을 보낼 수 있다 (앱 관리자 권한 필요, 별도 단계).

[현재 구현 상태 — 표시 전용(display-only)]
실행: 실제로 체인을 다시 실행하거나 execution_log를 갱신하는 로직은 이 모듈의
스코프가 아니다 — 지금은 "클릭을 받아서 화면에 반영"까지만 한다. 승인
(approve_chain) 버튼을 눌러도 실제로 차단된 체인이 (재)실행되거나
execution_log가 갱신되지 않는다. 즉 REVIEW로 차단된 공격의 "승인 → 실제
실행" 연결은 아직 구현되지 않았다(별도 과제). 이 모듈 자체에는 실행
트리거가 없다.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from urllib.parse import parse_qs

import requests
from fastapi import FastAPI, Header, HTTPException, Request

from purplebpf.common.config import get_slack_signing_secret

logger = logging.getLogger(__name__)

app = FastAPI()

MAX_REQUEST_AGE_SECONDS = 60 * 5  # 5분 넘게 지난 요청은 재전송(리플레이) 공격으로 보고 거부한다.
RESPONSE_URL_TIMEOUT_SECONDS = 10

DECISION_LABELS = {
    "approve_chain": ("✅", "승인됨"),
    "reject_chain": ("❌", "반려됨"),
}


@app.post("/slack/interactions")
async def handle_interaction(
    request: Request,
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
    action = (payload.get("actions") or [{}])[0]
    action_id = action.get("action_id")
    technique_id = action.get("value")
    username = (payload.get("user") or {}).get("username", "알 수 없는 사용자")

    if action_id not in DECISION_LABELS:
        logger.warning("알 수 없는 action_id: %s", action_id)
        raise HTTPException(status_code=400, detail="알 수 없는 action_id")

    # NOTE: 표시 전용 — approve_chain/reject_chain 둘 다 여기서 메시지 텍스트만
    #       "승인됨"/"반려됨"으로 갱신한다. 실제 체인 실행이나 execution_log
    #       갱신은 하지 않는다(미구현). "승인 → 실행" 연결은 별도 과제로 남아 있다.
    badge, label = DECISION_LABELS[action_id]
    logger.info("검수 결과: %s → %s (by %s)", technique_id, label, username)

    original_blocks = payload.get("message", {}).get("blocks", [])
    updated_blocks = _replace_action_block(original_blocks, badge, label, username)
    update_payload = {
        "replace_original": True,
        "text": f"{badge} {technique_id} — {label} (by {username})",
        "blocks": updated_blocks,
    }

    # response_url로 별도 요청을 보내서 원래 메시지를 갱신한다.
    # (요청에 바로 응답하는 방식보다 response_url 방식이 더 안정적으로 동작한다.)
    response_url = payload.get("response_url")
    if response_url:
        try:
            requests.post(response_url, json=update_payload, timeout=RESPONSE_URL_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            logger.error("response_url로 메시지 갱신 실패: %s", exc)
    else:
        logger.warning("payload에 response_url이 없다.")

    # Slack에는 빈 200 응답으로 "잘 받았다"는 것만 알려준다.
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


def _replace_action_block(blocks: list[dict], badge: str, label: str, username: str) -> list[dict]:
    # 마지막 'actions' 블록(승인/반려 버튼)을 결과 표시 텍스트로 교체한다.
    updated: list[dict] = []
    for block in blocks:
        if block.get("type") == "actions":
            updated.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{badge} {label}* — {username}",
                    },
                }
            )
        else:
            updated.append(block)
    return updated


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
