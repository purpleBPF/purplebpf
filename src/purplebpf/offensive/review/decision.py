"""Slack 2차 검수 [승인]/[반려] 클릭을 처리하는 공통 로직 (수신 방식과 무관).

수신부는 두 가지가 있다:
    - slack_socket.py   : Socket Mode (기본) — 우리 쪽이 Slack에 WebSocket을 먼저 연결한다.
    - slack_callback.py : HTTP Request URL (ngrok 등 공개 주소 필요) — 비상용으로 남겨둔다.
두 수신부 모두 Slack이 보낸 block_actions payload를 파싱한 뒤 이 모듈의
handle_block_actions()를 부른다. 그래서 판정/중복 처리/메시지 갱신 로직은 한 곳에만 있다.

상태 전이:
    PENDING(메시지 발송됨) → APPROVED | REJECTED
    한 메시지에서 한 번 결정되면 끝이다. 같은 메시지의 두 번째 클릭·재전송은
    DUPLICATE로 무시한다(멱등).

[실행 연결 상태 — 표시 전용]
승인을 받아도 실제 Docker 실행을 트리거하지 않는다. "승인 이벤트 수신"과
"실제 실행 완료"는 별개이므로 결과에 execution="NOT_LINKED"로 따로 기록한다.
실행 연결은 별도 과제다.
"""
from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

RESPONSE_URL_TIMEOUT_SECONDS = 10
MAX_REMEMBERED_DECISIONS = 1000  # 프로세스 메모리에 기억할 최근 결정 수

DECISION_LABELS = {
    "approve_chain": ("APPROVED", "✅", "승인됨"),
    "reject_chain": ("REJECTED", "❌", "반려됨"),
}

# 결과 status 값
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_DUPLICATE = "DUPLICATE"
STATUS_IGNORED = "IGNORED"


@dataclass(frozen=True)
class DecisionResult:
    status: str                 # APPROVED / REJECTED / DUPLICATE / IGNORED
    technique_id: str | None
    decision_key: str | None    # 멱등 키 (채널:메시지ts)
    user: str | None
    message_updated: bool = False
    execution: str = "NOT_LINKED"  # 승인 ≠ 실행. 실행 연결 전까지 항상 NOT_LINKED.


class DecisionStore:
    """메시지별로 이미 내려진 결정을 기억해서 중복 클릭/재전송을 막는다.

    프로세스 메모리 기반이다. 프로세스를 재시작하면 기억이 사라지므로,
    재시작 직후의 재클릭은 다시 처리될 수 있다(현재는 표시 전용이라 영향은
    메시지 문구 갱신뿐). 실행과 연결할 때는 DB 기반 저장소로 바꿔야 한다.
    """

    def __init__(self, max_size: int = MAX_REMEMBERED_DECISIONS) -> None:
        self._max_size = max_size
        self._decisions: OrderedDict[str, str] = OrderedDict()
        self._lock = threading.Lock()

    def claim(self, key: str, status: str) -> str | None:
        """key에 대한 결정을 선점한다. 이미 결정돼 있으면 기존 status를 반환한다."""
        with self._lock:
            existing = self._decisions.get(key)
            if existing is not None:
                return existing
            self._decisions[key] = status
            while len(self._decisions) > self._max_size:
                self._decisions.popitem(last=False)
            return None

    def release(self, key: str) -> None:
        with self._lock:
            self._decisions.pop(key, None)


_default_store = DecisionStore()


def handle_block_actions(
    payload: dict,
    store: DecisionStore | None = None,
    post=requests.post,
) -> DecisionResult:
    """block_actions payload 하나를 처리한다. 수신부(Socket/HTTP)와 무관하다.

    호출 전에 수신부가 Slack에 ACK(Socket Mode는 envelope_id 응답, HTTP는 200)를
    이미 보냈거나 곧 보낸다고 가정한다. 여기서는 Slack 3초 제한을 신경 쓰지 않는다.
    """
    store = store or _default_store

    if payload.get("type") != "block_actions":
        logger.info("처리 대상이 아닌 interactive payload: type=%s", payload.get("type"))
        return DecisionResult(STATUS_IGNORED, None, None, None)

    action = (payload.get("actions") or [{}])[0]
    action_id = action.get("action_id")
    technique_id = action.get("value")
    user = _username(payload)

    if action_id not in DECISION_LABELS:
        logger.warning("알 수 없는 action_id: %s", action_id)
        return DecisionResult(STATUS_IGNORED, technique_id, None, user)

    status, badge, label = DECISION_LABELS[action_id]
    key = decision_key(payload)

    if key is not None:
        previous = store.claim(key, status)
        if previous is not None:
            logger.info(
                "중복 검수 이벤트 무시: key=%s technique=%s 기존=%s 이번=%s (by %s)",
                key, technique_id, previous, status, user,
            )
            return DecisionResult(STATUS_DUPLICATE, technique_id, key, user)
    else:
        logger.warning("멱등 키를 만들 수 없는 payload — 중복 검사 없이 처리한다.")

    logger.info("검수 결과: %s → %s (by %s, key=%s, execution=NOT_LINKED)", technique_id, status, user, key)

    updated = _update_original_message(payload, technique_id, badge, label, user, post)
    return DecisionResult(status, technique_id, key, user, message_updated=updated)


def decision_key(payload: dict) -> str | None:
    """메시지 단위 멱등 키. 한 메시지(=한 검수 요청)에는 결정이 하나만 있어야 한다.

    인터랙션 payload에는 event_id가 없으므로 (채널, 메시지 ts)를 쓴다.
    incoming webhook 메시지도 container.message_ts / channel_id가 채워져 온다.
    """
    container = payload.get("container") or {}
    message = payload.get("message") or {}
    channel = container.get("channel_id") or (payload.get("channel") or {}).get("id")
    message_ts = container.get("message_ts") or message.get("ts")
    if not message_ts:
        return None
    return f"{channel or '-'}:{message_ts}"


def build_update_payload(original_blocks: list[dict], technique_id: str | None, badge: str, label: str, user: str) -> dict:
    return {
        "replace_original": True,
        "text": f"{badge} {technique_id} — {label} (by {user})",
        "blocks": replace_action_block(original_blocks, badge, label, user),
    }


def replace_action_block(blocks: list[dict], badge: str, label: str, user: str) -> list[dict]:
    """승인/반려 버튼(actions 블록)을 결과 표시 텍스트로 교체한다."""
    updated: list[dict] = []
    for block in blocks:
        if block.get("type") == "actions":
            updated.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*{badge} {label}* — {user}"},
                }
            )
        else:
            updated.append(block)
    return updated


def _update_original_message(payload: dict, technique_id, badge: str, label: str, user: str, post) -> bool:
    # 메시지 갱신은 Socket Mode여도 WebSocket이 아니라 response_url(HTTPS)로 보낸다.
    response_url = payload.get("response_url")
    if not response_url:
        logger.warning("payload에 response_url이 없어 원본 메시지를 갱신하지 못했다.")
        return False

    original_blocks = (payload.get("message") or {}).get("blocks", [])
    body = build_update_payload(original_blocks, technique_id, badge, label, user)
    try:
        response = post(response_url, json=body, timeout=RESPONSE_URL_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        logger.error("response_url로 메시지 갱신 실패 (네트워크): %s", type(exc).__name__)
        return False

    status_code = getattr(response, "status_code", 200)
    if status_code != 200:
        logger.error("response_url로 메시지 갱신 실패 (status=%s)", status_code)
        return False
    return True


def _username(payload: dict) -> str:
    user = payload.get("user") or {}
    return user.get("username") or user.get("name") or user.get("id") or "알 수 없는 사용자"
