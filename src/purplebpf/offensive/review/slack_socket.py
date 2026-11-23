"""Slack Socket Mode 수신부 — ngrok/공개 URL 없이 [승인]/[반려] 클릭을 받는다.

동작 방식:
    1. App-level Token(xapp-...)으로 apps.connections.open을 호출해 WebSocket URL을 받는다.
    2. 그 URL로 우리 쪽에서 아웃바운드 WebSocket 연결을 연다.
    3. Slack은 버튼 클릭(interactive)·이벤트를 이 연결로 envelope에 담아 보낸다.
    4. 받자마자 envelope_id로 ACK를 돌려준다(3초 안에 안 하면 Slack이 재전송한다).
    5. 실제 처리는 decision.handle_block_actions()에 맡긴다(HTTP 수신부와 같은 로직).

메시지 발송(slack_notify.py, incoming webhook)과 원본 메시지 갱신(response_url)은
여전히 HTTPS다. Socket Mode가 바꾸는 건 "Slack → 우리" 방향의 수신 경로뿐이다.

요청 서명(Signing Secret) 검증이 필요 없다: 연결 자체를 우리가 App-level Token으로
열었기 때문에 이 연결로 오는 메시지는 Slack이 보낸 것이다.

실행:
    python -m purplebpf.offensive.review.slack_socket

연결 끊김은 slack_sdk 내장 클라이언트가 자동으로 재연결한다(auto_reconnect).
처음 연결부터 실패하면 토큰/권한 오류는 즉시 종료하고, 네트워크 오류는 백오프로 재시도한다.
"""
from __future__ import annotations

import logging
import signal
import threading
import time

from purplebpf.common.config import get_slack_app_token
from purplebpf.offensive.review.decision import DecisionStore, handle_block_actions

logger = logging.getLogger(__name__)

INITIAL_CONNECT_MAX_ATTEMPTS = 5
INITIAL_CONNECT_BACKOFF_SECONDS = 2  # 2, 4, 8, 16 ... 초
# 재시도해도 소용없는 오류(토큰/권한 문제)는 바로 종료한다.
FATAL_AUTH_ERRORS = {"invalid_auth", "not_authed", "account_inactive", "token_revoked", "missing_scope", "not_allowed_token_type"}


def build_listener(store: DecisionStore | None = None, handler=handle_block_actions):
    """SocketModeClient에 붙일 리스너를 만든다. 테스트에서 handler를 바꿔 끼울 수 있다."""
    from slack_sdk.socket_mode.response import SocketModeResponse

    store = store or DecisionStore()

    def listener(client, req) -> None:
        # 1) ACK 먼저 — 처리 실패와 무관하게 "받았다"는 것만 알린다.
        #    ACK가 늦으면 Slack이 같은 envelope를 재전송하고, 사용자 화면에 경고가 뜬다.
        client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))

        retry = getattr(req, "retry_attempt", None)
        if retry:
            logger.info("Slack 재전송 envelope 수신: type=%s retry_attempt=%s reason=%s", req.type, retry, getattr(req, "retry_reason", None))

        if req.type != "interactive":
            logger.debug("처리 대상 아님(ACK만 보냄): type=%s", req.type)
            return

        # 2) 실제 처리. 예외가 나도 리스너 스레드가 죽지 않게 잡아서 로그만 남긴다.
        try:
            result = handler(req.payload or {}, store=store)
        except Exception:
            logger.exception("검수 이벤트 처리 실패 (envelope_id=%s)", req.envelope_id)
            return
        logger.info(
            "검수 이벤트 처리 완료: status=%s technique=%s key=%s message_updated=%s execution=%s",
            result.status, result.technique_id, result.decision_key, result.message_updated, result.execution,
        )

    return listener


def build_client(app_token: str):
    from slack_sdk.socket_mode.builtin import SocketModeClient

    client = SocketModeClient(app_token=app_token, logger=logging.getLogger("slack_sdk.socket_mode"), auto_reconnect_enabled=True)
    client.socket_mode_request_listeners.append(build_listener())
    client.on_error_listeners.append(lambda exc: logger.warning("Socket Mode 오류: %s", type(exc).__name__))
    client.on_close_listeners.append(lambda code, reason: logger.warning("Socket Mode 연결 닫힘 (code=%s, reason=%s) — 자동 재연결 시도", code, reason))
    return client


def connect_with_retry(client, max_attempts: int = INITIAL_CONNECT_MAX_ATTEMPTS, sleep=time.sleep) -> None:
    from slack_sdk.errors import SlackApiError

    for attempt in range(1, max_attempts + 1):
        try:
            client.connect()
            logger.info("Slack Socket Mode 연결됨 (attempt=%s)", attempt)
            return
        except SlackApiError as exc:
            error = exc.response.get("error") if exc.response is not None else None
            if error in FATAL_AUTH_ERRORS:
                raise RuntimeError(
                    f"Slack 토큰/권한 오류({error}): SLACK_APP_TOKEN이 xapp- 토큰인지, connections:write 스코프가 있는지, 앱에서 Socket Mode가 켜져 있는지 확인하라."
                ) from exc
            logger.warning("Socket Mode 연결 실패 (attempt=%s, error=%s)", attempt, error)
        except Exception as exc:  # 네트워크 오류 등
            logger.warning("Socket Mode 연결 실패 (attempt=%s): %s", attempt, type(exc).__name__)

        if attempt < max_attempts:
            sleep(INITIAL_CONNECT_BACKOFF_SECONDS * 2 ** (attempt - 1))

    raise RuntimeError(f"Slack Socket Mode 연결 실패: {max_attempts}회 재시도 후 포기")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    client = build_client(get_slack_app_token())

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    connect_with_retry(client)
    logger.info("승인/반려 이벤트 대기 중 (Ctrl+C로 종료)")
    stop.wait()

    logger.info("종료 중...")
    client.close()


if __name__ == "__main__":
    main()
