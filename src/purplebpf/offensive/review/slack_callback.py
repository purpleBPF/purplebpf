"""Slack 2차 검수 메시지의 [승인]/[반려] 버튼 클릭을 수신하는 콜백 서버.

Slack은 버튼이 눌리면 여기 등록된 Request URL로 POST 요청을 보낸다. 이 모듈은
그 요청을 받아서:
1. 진짜 Slack이 보낸 요청인지 서명을 검증하고
2. 어떤 기법(technique_id)에 대해 승인/반려가 눌렸는지 확인하고
3. 원래 Slack 메시지를 "✅ 승인됨" / "❌ 반려됨"으로 바꿔서 응답한다.

로컬(WSL2)에서 이 서버를 띄운 뒤, ngrok 같은 도구로 외부에 노출시키고,
그 ngrok 주소를 Slack 앱 설정의 'Interactivity & Shortcuts' > Request URL에
등록해야 실제로 Slack이 요청을 보낼 수 있다 (앱 관리자 권한 필요, 별도 단계).

[현재 구현 상태 — 결정 영속화(persist), 실행은 미포함]
버튼 value에 담긴 review_id로 review_decisions 행을 APPROVED/REJECTED로 갱신하고
(review_store.record_decision), 누가/언제 결정했는지(decided_by/decided_at)를
남긴다. 다만 실제로 차단된 체인을 (재)실행하거나 execution_log를 갱신하는 일은
여전히 이 모듈의 스코프가 아니다 — "승인 → 실제 실행" 연결은 워크스트림 C가
review_decisions/review_store 인터페이스를 소비해 처리한다. 이 모듈 자체에는
실행 트리거가 없다.
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
from purplebpf.offensive.review import review_store

logger = logging.getLogger(__name__)

app = FastAPI()

MAX_REQUEST_AGE_SECONDS = 60 * 5  # 5분 넘게 지난 요청은 재전송(리플레이) 공격으로 보고 거부한다.
RESPONSE_URL_TIMEOUT_SECONDS = 10

DECISION_LABELS = {
    "approve_chain": ("✅", "승인됨"),
    "reject_chain": ("❌", "반려됨"),
}

# action_id → review_decisions.status 전이값.
DECISION_STATUS = {
    "approve_chain": review_store.STATUS_APPROVED,
    "reject_chain": review_store.STATUS_REJECTED,
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
    # 버튼 value에는 review_id가 들어있다(slack_notify가 심어둔다). 영속화가
    # 실패했던 레거시 알림은 technique_id가 들어있을 수 있다 — 그 경우 DB 갱신은
    # 조용히 건너뛰고 표시만 갱신한다.
    review_id = action.get("value")
    username = (payload.get("user") or {}).get("username", "알 수 없는 사용자")

    if action_id not in DECISION_LABELS:
        logger.warning("알 수 없는 action_id: %s", action_id)
        raise HTTPException(status_code=400, detail="알 수 없는 action_id")

    # review_id로 결정을 영속화한다(status=APPROVED/REJECTED, decided_by, decided_at).
    # 실제 체인 실행/execution_log 갱신은 하지 않는다 — 그 연결은 워크스트림 C가
    # review_decisions/review_store를 소비해 처리한다.
    review = _record_review_decision(review_id, DECISION_STATUS[action_id], username)
    # 표시용 technique_id: 저장된 행에서 가져오고, 없으면 value를 그대로 쓴다.
    technique_id = review.get("technique_id") if review else review_id

    badge, label = DECISION_LABELS[action_id]
    logger.info("검수 결과: %s (review=%s) → %s (by %s)", technique_id, review_id, label, username)

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


def _record_review_decision(review_id: str | None, status: str, username: str) -> dict | None:
    """review_id로 결정을 저장한다. 저장에 실패해도 콜백 응답은 막지 않는다.

    DB가 없거나(레거시 알림/미구성) 해당 행이 없으면 None을 돌려주고, 이 경우
    메시지 표시만 갱신된다. 버튼 클릭에 500으로 응답하면 Slack이 재시도하며
    "작업 실패"를 띄우므로, 영속화 오류는 삼키고 로깅만 한다.
    """
    if not review_id:
        logger.warning("버튼 value에 review_id가 없다 — 결정 저장을 건너뛴다.")
        return None
    try:
        review = review_store.record_decision(review_id, status, username)
    except Exception as exc:
        logger.error("검수 결정 저장 실패 (review_id=%s): %s", review_id, type(exc).__name__)
        return None
    if review is None:
        logger.warning("review_id=%s 에 해당하는 검수건이 없다 — 표시만 갱신한다.", review_id)
    return review


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
