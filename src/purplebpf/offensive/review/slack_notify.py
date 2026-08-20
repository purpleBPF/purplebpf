"""GraphRAG의 2차 검수 알림 — 1차 필터를 통과한 공격 체인을 Slack Block Kit 메시지로 전송한다.

이 단계는 Slack 채널에 메시지를 띄우는 것까지가 범위다. 승인/반려 버튼은 UI만
구성하며, 버튼 클릭 콜백 수신(FastAPI, ngrok 등)은 다음 단계에서 다룬다.
실제 체인 실행은 이 모듈에 포함하지 않는다.
"""
from __future__ import annotations

import argparse
import json
import logging

import requests

from purplebpf.common.config import get_slack_webhook_url

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 10
MAX_BLOCK_TEXT_LENGTH = 2900  # Slack section text object의 3000자 제한에 여유를 둔다
MAX_REVIEW_COMMAND_LENGTH = 500

VERDICT_BADGES = {"PASS": "✅", "REVIEW": "🟡", "REJECT": "⛔"}


def notify_review(chain: dict, verdict: dict) -> bool:
    webhook_url = get_slack_webhook_url()
    payload = {
        "text": f"2차 검수 요청 — {chain.get('technique_id', 'UNKNOWN')}",
        "blocks": _build_blocks(chain, verdict),
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        logger.error("Slack 알림 전송 실패 (네트워크 오류): %s", exc)
        return False

    if response.status_code != 200:
        logger.error("Slack 알림 전송 실패 (status=%s): %s", response.status_code, response.text)
        return False

    return True


def notify_scenario_review(chain: dict, source: str, review_result: dict) -> dict:
    """Adapt a REVIEW result to the existing Slack notification contract."""
    context = _review_context(chain, source, review_result)
    verdict = {
        "verdict": "REVIEW",
        "reasons": context["reason_texts"],
        "review_context": context,
    }
    try:
        sent = notify_review(chain, verdict)
    except RuntimeError as exc:
        if "SLACK_WEBHOOK_URL" in str(exc):
            return {"type": "SLACK", "status": "NOT_CONFIGURED"}
        logger.error("Slack REVIEW 알림 준비 실패: %s", type(exc).__name__)
        return {"type": "SLACK", "status": "FAILED"}
    except Exception as exc:
        logger.error("Slack REVIEW 알림 실패: %s", type(exc).__name__)
        return {"type": "SLACK", "status": "FAILED"}
    return {"type": "SLACK", "status": "SENT" if sent else "FAILED"}


def _review_context(chain: dict, source: str, review_result: dict) -> dict:
    details = (
        _validator_review_details(review_result)
        if source == "RULE_VALIDATOR"
        else _first_filter_review_details(review_result)
    )
    levels = sorted({detail["level"] for detail in details if detail.get("level")})
    reasons = []
    for detail in details:
        reason = detail.get("reason")
        if reason and reason not in reasons:
            reasons.append(reason)
    if not reasons:
        reasons.append("REVIEW")

    related = next(
        (detail for detail in details if detail.get("step") is not None),
        details[0] if details else {},
    )
    step = related.get("step")
    command = related.get("command") or _command_for_step(chain, step)
    return {
        "source": source,
        "levels": levels or [source],
        "reason_texts": reasons,
        "step": step,
        "command": _truncate(command, MAX_REVIEW_COMMAND_LENGTH) if command else None,
        "execution": "Blocked before Docker execution",
        "next_action": "Human review required",
    }


def _first_filter_review_details(review_result: dict) -> list[dict]:
    details: list[dict] = []
    for reason in review_result.get("reasons") or []:
        details.append({"level": "FIRST_FILTER", "reason": str(reason)})
    for check_name, check in (review_result.get("checks") or {}).items():
        if not isinstance(check, dict) or check.get("passed") is not False:
            continue
        for issue in check.get("issues") or []:
            if isinstance(issue, dict):
                reason = issue.get("code") or issue.get("message") or check_name
                details.append(
                    {
                        "level": "FIRST_FILTER",
                        "reason": str(reason),
                        "step": issue.get("step_order"),
                    }
                )
            else:
                details.append({"level": "FIRST_FILTER", "reason": str(issue)})
    return details


def _validator_review_details(validation: dict) -> list[dict]:
    details: list[dict] = []
    for key, label in (("level1", "LEVEL1"), ("level2", "LEVEL2"), ("level3", "LEVEL3")):
        level = validation.get(key)
        if not isinstance(level, dict) or level.get("status") != "REVIEW":
            continue
        errors = level.get("errors") or []
        if not errors:
            details.append({"level": label, "reason": "REVIEW"})
            continue
        for error in errors:
            if not isinstance(error, dict):
                details.append({"level": label, "reason": str(error)})
                continue
            reason = error.get("code") or error.get("message") or "REVIEW"
            details.append(
                {
                    "level": label,
                    "reason": str(reason),
                    "step": error.get("step"),
                    "command": error.get("command"),
                }
            )
    if not details:
        final = validation.get("final")
        if isinstance(final, dict):
            details.append(
                {
                    "level": "FINAL",
                    "reason": str(final.get("reason") or final.get("status") or "REVIEW"),
                }
            )
    return details


def _command_for_step(chain: dict, order) -> str | None:
    if order is None:
        return None
    for step in chain.get("steps") or []:
        if isinstance(step, dict) and step.get("order") == order:
            command = step.get("command")
            return command if isinstance(command, str) else None
    return None


def _build_blocks(chain: dict, verdict: dict) -> list[dict]:
    technique_id = chain.get("technique_id", "UNKNOWN")
    goal = chain.get("goal", "(없음)")
    steps = chain.get("steps") or []
    verdict_label = verdict.get("verdict", "UNKNOWN")
    badge = VERDICT_BADGES.get(verdict_label, "❔")
    review_context = verdict.get("review_context")
    verdict_heading = "검토 판정" if isinstance(review_context, dict) else "1차 필터 판정"

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🛡️ 2차 검수 요청 — {technique_id}", "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{verdict_heading}:* {badge} `{verdict_label}`"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*목표:*\n{goal}"},
        },
    ]

    reasons = verdict.get("reasons") or []
    if reasons:
        reasons_text = "\n".join(f"• {reason}" for reason in reasons)
        reasons_heading = "REVIEW 사유" if isinstance(review_context, dict) else "필터 사유"
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{reasons_heading}:*\n{_truncate(reasons_text)}",
                },
            }
        )

    if isinstance(review_context, dict):
        source = review_context.get("source", "UNKNOWN")
        levels = ", ".join(review_context.get("levels") or ["UNKNOWN"])
        reason_text = ", ".join(review_context.get("reason_texts") or ["REVIEW"])
        step = review_context.get("step")
        command = review_context.get("command")
        context_lines = [
            f"*Review Source:* `{source}`",
            f"*Review Level:* `{levels}`",
            f"*Reason:* {reason_text}",
        ]
        if step is not None:
            context_lines.append(f"*Related Step:* `{step}`")
        if command:
            context_lines.append(f"*Command:* `{command}`")
        context_lines.extend(
            [
                f"*Execution:* {review_context.get('execution')}",
                f"*Next:* {review_context.get('next_action')}",
            ]
        )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": _truncate("\n".join(context_lines)),
                },
            }
        )

    blocks.append({"type": "divider"})

    steps_text = "\n".join(
        f"{step.get('order')}. `{step.get('command')}` — {step.get('purpose')}" for step in steps
    )
    blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*단계 ({len(steps)}개):*\n{_truncate(steps_text)}",
            },
        }
    )

    blocks.append({"type": "divider"})
    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ 승인", "emoji": True},
                    "style": "primary",
                    "action_id": "approve_chain",
                    "value": technique_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ 반려", "emoji": True},
                    "style": "danger",
                    "action_id": "reject_chain",
                    "value": technique_id,
                },
            ],
        }
    )

    return blocks


def _truncate(text: str, limit: int = MAX_BLOCK_TEXT_LENGTH) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 20].rstrip() + "\n... (생략됨)"


SAMPLE_CHAIN = {
    "technique_id": "T1611",
    "goal": "마운트된 호스트 루트로 chroot하여 컨테이너를 탈출한다.",
    "steps": [
        {"order": 1, "command": "mount --bind / /mnt/host", "purpose": "호스트 루트 파일시스템을 마운트한다."},
        {"order": 2, "command": "chroot /mnt/host", "purpose": "마운트된 호스트로 루트를 전환해 탈출한다."},
    ],
}

SAMPLE_VERDICT = {
    "verdict": "PASS",
    "checks": {
        "structure": {"passed": True, "issues": []},
        "syntax": {"passed": True, "issues": []},
        "ordering": {"passed": True, "issues": []},
    },
    "reasons": [],
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="1차 필터를 통과한 공격 체인을 Slack 2차 검수 채널로 전송한다"
    )
    parser.add_argument(
        "technique_id",
        nargs="?",
        default="T1611",
        help="검증할 대상 Technique ID (기본: T1611). --sample과 함께 쓰면 무시된다.",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="gemma/필터 없이 하드코딩된 샘플 체인으로 전송 테스트",
    )
    args = parser.parse_args()

    if args.sample:
        chain, verdict = SAMPLE_CHAIN, SAMPLE_VERDICT
    else:
        from purplebpf.offensive.filter.first_filter import filter_chain
        from purplebpf.offensive.generation.generator import generate_chain

        chain = generate_chain(args.technique_id)
        verdict = filter_chain(chain)

    print(json.dumps({"chain": chain, "verdict": verdict}, indent=2, ensure_ascii=False))
    success = notify_review(chain, verdict)
    print("Slack 전송 성공" if success else "Slack 전송 실패")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
