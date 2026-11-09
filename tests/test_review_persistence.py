"""워크스트림 B — 2차 검수 결정 영속화 단위테스트.

Postgres·Slack 없이 돈다: sqlite(StaticPool 인메모리) SQLAlchemy 엔진과 가짜
Slack payload/서명으로 서명검증·payload 파싱(review_id 추출)·결정 영속화를 검증한다.
tests/test_executor_review_notification.py의 mock/stub 패턴을 따른다.
"""
import asyncio
import hashlib
import hmac
import json
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

import sqlalchemy as sa
from sqlalchemy.pool import StaticPool

from purplebpf.offensive.review import review_store, slack_callback, slack_notify


CHAIN = {
    "technique_id": "T1611",
    "round_id": 3,
    "goal": "마운트된 호스트 루트로 chroot하여 컨테이너를 탈출한다.",
    "steps": [
        {"order": 1, "command": "mount --bind / /mnt/host", "purpose": "호스트 루트 마운트."},
        {"order": 2, "command": "chroot /mnt/host", "purpose": "루트 전환으로 탈출."},
    ],
}

VALIDATOR_REVIEW = {
    "level1": {"status": "PASS"},
    "level2": {
        "status": "REVIEW",
        "errors": [{"code": "UNSUPPORTED_COMMAND", "step": 2, "command": "chroot /mnt/host"}],
    },
    "level3": {"status": "PASS", "errors": []},
}


def make_engine():
    """여러 connect()/begin() 호출이 같은 인메모리 DB를 보도록 StaticPool을 쓴다."""
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    review_store.create_all(engine)
    return engine


def sign(secret: str, timestamp: str, body: bytes) -> str:
    base = f"v0:{timestamp}:{body.decode('utf-8')}".encode("utf-8")
    return "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()


class FakeRequest:
    """slack_callback.handle_interaction은 await request.body()만 쓴다."""

    def __init__(self, body: bytes):
        self._body = body

    async def body(self) -> bytes:
        return self._body


class ReviewStoreTests(unittest.TestCase):
    def setUp(self):
        self.engine = make_engine()

    def test_create_pending_review_inserts_pending_row(self):
        review_id = review_store.create_pending_review(
            technique_id="T1611",
            round_id=3,
            source=review_store.SOURCE_RULE_VALIDATOR,
            chain_json=CHAIN,
            engine=self.engine,
        )
        self.assertTrue(review_id)
        row = review_store.get_review(review_id, engine=self.engine)
        self.assertEqual(row["status"], "PENDING")
        self.assertEqual(row["technique_id"], "T1611")
        self.assertEqual(row["round_id"], 3)
        self.assertEqual(row["source"], "RULE_VALIDATOR")
        # chain_json에 차단된 체인 전체가 그대로 보존된다(C가 재실행에 소비).
        self.assertEqual(row["chain_json"], CHAIN)
        self.assertIsNone(row["decided_by"])
        self.assertIsNone(row["decided_at"])

    def test_create_pending_review_rejects_unknown_source(self):
        with self.assertRaises(ValueError):
            review_store.create_pending_review(
                technique_id="T1611",
                round_id=None,
                source="NONSENSE",
                chain_json=CHAIN,
                engine=self.engine,
            )

    def test_record_decision_approves_with_decider(self):
        review_id = review_store.create_pending_review(
            technique_id="T1611",
            round_id=None,
            source=review_store.SOURCE_FIRST_FILTER,
            chain_json=CHAIN,
            engine=self.engine,
        )
        updated = review_store.record_decision(
            review_id, review_store.STATUS_APPROVED, "alice", engine=self.engine
        )
        self.assertEqual(updated["status"], "APPROVED")
        self.assertEqual(updated["decided_by"], "alice")
        self.assertIsNotNone(updated["decided_at"])

    def test_record_decision_rejects_invalid_status(self):
        review_id = review_store.create_pending_review(
            technique_id="T1611",
            round_id=None,
            source=review_store.SOURCE_RULE_VALIDATOR,
            chain_json=CHAIN,
            engine=self.engine,
        )
        # PENDING으로 되돌리거나 임의 상태로 바꾸는 것은 허용하지 않는다.
        with self.assertRaises(ValueError):
            review_store.record_decision(
                review_id, "PENDING", "alice", engine=self.engine
            )

    def test_record_decision_unknown_id_returns_none(self):
        self.assertIsNone(
            review_store.record_decision(
                "00000000-0000-0000-0000-000000000000",
                review_store.STATUS_APPROVED,
                "alice",
                engine=self.engine,
            )
        )

    def test_get_review_unknown_id_returns_none(self):
        self.assertIsNone(review_store.get_review("does-not-exist", engine=self.engine))

    def test_list_approved_pending_execution_only_returns_approved(self):
        approved = []
        for _ in range(2):
            rid = review_store.create_pending_review(
                technique_id="T1611",
                round_id=1,
                source=review_store.SOURCE_RULE_VALIDATOR,
                chain_json=CHAIN,
                engine=self.engine,
            )
            review_store.record_decision(
                rid, review_store.STATUS_APPROVED, "alice", engine=self.engine
            )
            approved.append(rid)

        rejected = review_store.create_pending_review(
            technique_id="T1611",
            round_id=1,
            source=review_store.SOURCE_RULE_VALIDATOR,
            chain_json=CHAIN,
            engine=self.engine,
        )
        review_store.record_decision(
            rejected, review_store.STATUS_REJECTED, "bob", engine=self.engine
        )
        pending = review_store.create_pending_review(
            technique_id="T1611",
            round_id=1,
            source=review_store.SOURCE_RULE_VALIDATOR,
            chain_json=CHAIN,
            engine=self.engine,
        )

        rows = review_store.list_approved_pending_execution(engine=self.engine)
        returned_ids = {row["review_id"] for row in rows}
        self.assertEqual(returned_ids, set(approved))
        self.assertNotIn(rejected, returned_ids)
        self.assertNotIn(pending, returned_ids)


class SlackNotifyPersistenceTests(unittest.TestCase):
    def test_notify_persists_pending_and_sets_button_value(self):
        engine = make_engine()
        with patch.object(review_store, "build_db_engine", return_value=engine), patch.object(
            slack_notify, "notify_review", return_value=True
        ) as send:
            result = slack_notify.notify_scenario_review(CHAIN, "RULE_VALIDATOR", VALIDATOR_REVIEW)

        review_id = result["review_id"]
        self.assertTrue(review_id)
        self.assertEqual(result["status"], "SENT")

        row = review_store.get_review(review_id, engine=engine)
        self.assertEqual(row["status"], "PENDING")
        self.assertEqual(row["source"], "RULE_VALIDATOR")
        self.assertEqual(row["technique_id"], "T1611")
        self.assertEqual(row["round_id"], 3)
        self.assertEqual(row["chain_json"], CHAIN)

        # Slack 버튼 value == review_id (표시 텍스트엔 technique_id 유지)
        sent_chain, verdict = send.call_args.args
        blocks = slack_notify._build_blocks(sent_chain, verdict)
        actions = next(b for b in blocks if b.get("type") == "actions")
        values = {element["value"] for element in actions["elements"]}
        self.assertEqual(values, {review_id})
        self.assertIn("T1611", json.dumps(blocks, ensure_ascii=False))

    def test_notify_degrades_gracefully_when_persistence_fails(self):
        # DB 삽입이 실패해도 Slack 전송은 막지 않고, 버튼 value는 technique_id로 폴백한다.
        with patch.object(
            review_store, "create_pending_review", side_effect=RuntimeError("no db")
        ), patch.object(slack_notify, "notify_review", return_value=True) as send:
            result = slack_notify.notify_scenario_review(CHAIN, "RULE_VALIDATOR", VALIDATOR_REVIEW)

        self.assertEqual(result["status"], "SENT")
        self.assertIsNone(result["review_id"])
        sent_chain, verdict = send.call_args.args
        blocks = slack_notify._build_blocks(sent_chain, verdict)
        actions = next(b for b in blocks if b.get("type") == "actions")
        values = {element["value"] for element in actions["elements"]}
        self.assertEqual(values, {"T1611"})


class SlackSignatureTests(unittest.TestCase):
    def test_valid_signature_passes(self):
        secret, ts, body = "s3cret", str(int(time.time())), b"payload=%7B%7D"
        with patch.object(slack_callback, "get_slack_signing_secret", return_value=secret):
            # 예외가 나지 않으면 통과
            slack_callback._verify_slack_signature(
                raw_body=body, timestamp=ts, signature=sign(secret, ts, body)
            )

    def test_bad_signature_is_rejected(self):
        secret, ts, body = "s3cret", str(int(time.time())), b"payload=%7B%7D"
        with patch.object(slack_callback, "get_slack_signing_secret", return_value=secret):
            with self.assertRaises(Exception) as ctx:
                slack_callback._verify_slack_signature(
                    raw_body=body, timestamp=ts, signature="v0=deadbeef"
                )
        self.assertEqual(getattr(ctx.exception, "status_code", None), 401)

    def test_stale_timestamp_is_rejected(self):
        secret = "s3cret"
        body = b"payload=%7B%7D"
        old_ts = str(int(time.time()) - slack_callback.MAX_REQUEST_AGE_SECONDS - 10)
        with patch.object(slack_callback, "get_slack_signing_secret", return_value=secret):
            with self.assertRaises(Exception) as ctx:
                slack_callback._verify_slack_signature(
                    raw_body=body, timestamp=old_ts, signature=sign(secret, old_ts, body)
                )
        self.assertEqual(getattr(ctx.exception, "status_code", None), 400)

    def test_missing_headers_are_rejected(self):
        with self.assertRaises(Exception):
            slack_callback._verify_slack_signature(
                raw_body=b"x", timestamp=None, signature=None
            )

    def test_parse_payload_extracts_review_id(self):
        payload = {"actions": [{"action_id": "approve_chain", "value": "rid-42"}]}
        body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
        parsed = slack_callback._parse_payload(body)
        self.assertEqual(parsed["actions"][0]["value"], "rid-42")

    def test_parse_payload_missing_field_raises(self):
        with self.assertRaises(Exception):
            slack_callback._parse_payload(b"not_payload=1")


class SlackCallbackPersistenceTests(unittest.TestCase):
    def _run_callback(self, engine, action_id, review_id, secret="s3cret"):
        payload = {
            "actions": [{"action_id": action_id, "value": review_id}],
            "user": {"username": "alice"},
            "message": {"blocks": [{"type": "actions", "elements": []}]},
            "response_url": "https://hooks.slack.test/response",
        }
        body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
        ts = str(int(time.time()))
        signature = sign(secret, ts, body)
        with patch.object(slack_callback, "get_slack_signing_secret", return_value=secret), \
            patch.object(review_store, "build_db_engine", return_value=engine), \
            patch.object(slack_callback, "requests") as fake_requests:
            asyncio.run(
                slack_callback.handle_interaction(
                    FakeRequest(body),
                    x_slack_signature=signature,
                    x_slack_request_timestamp=ts,
                )
            )
        return fake_requests

    def test_approve_button_persists_approved_decision(self):
        engine = make_engine()
        review_id = review_store.create_pending_review(
            technique_id="T1611",
            round_id=3,
            source=review_store.SOURCE_RULE_VALIDATOR,
            chain_json=CHAIN,
            engine=engine,
        )
        fake_requests = self._run_callback(engine, "approve_chain", review_id)

        row = review_store.get_review(review_id, engine=engine)
        self.assertEqual(row["status"], "APPROVED")
        self.assertEqual(row["decided_by"], "alice")
        self.assertIsNotNone(row["decided_at"])
        # 메시지 표시 갱신은 response_url로 시도된다(실행은 하지 않는다).
        fake_requests.post.assert_called_once()

    def test_reject_button_persists_rejected_decision(self):
        engine = make_engine()
        review_id = review_store.create_pending_review(
            technique_id="T1611",
            round_id=3,
            source=review_store.SOURCE_RULE_VALIDATOR,
            chain_json=CHAIN,
            engine=engine,
        )
        self._run_callback(engine, "reject_chain", review_id)
        row = review_store.get_review(review_id, engine=engine)
        self.assertEqual(row["status"], "REJECTED")
        self.assertEqual(row["decided_by"], "alice")

    def test_unknown_review_id_does_not_crash_callback(self):
        engine = make_engine()
        # 존재하지 않는 review_id로 눌러도 500이 아니라 조용히 표시만 갱신한다.
        fake_requests = self._run_callback(engine, "approve_chain", "missing-id")
        fake_requests.post.assert_called_once()


if __name__ == "__main__":
    unittest.main()
