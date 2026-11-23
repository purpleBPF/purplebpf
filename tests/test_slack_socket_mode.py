"""Slack Socket Mode 전환 테스트 — 공통 판정 로직, Socket 리스너 ACK, HTTP 폴백.

실제 Slack에 붙지 않는다. SocketModeClient/response_url은 가짜 객체로 대체한다.
"""
import os
import sys
import types
import unittest
from unittest.mock import Mock


def _install_import_stub(name, **attributes):
    if name in sys.modules:
        return
    try:
        __import__(name)
    except ModuleNotFoundError:
        module = types.ModuleType(name)
        for attribute, value in attributes.items():
            setattr(module, attribute, value)
        sys.modules[name] = module


_install_import_stub("sqlalchemy", Engine=object, create_engine=Mock(), text=lambda statement: statement)
_install_import_stub("dotenv", load_dotenv=Mock())
_install_import_stub("neo4j", Driver=object, GraphDatabase=Mock())

from purplebpf.common import config  # noqa: E402
from purplebpf.offensive.review import decision  # noqa: E402
from purplebpf.offensive.review.decision import DecisionStore, handle_block_actions  # noqa: E402


def _payload(action_id="approve_chain", message_ts="1700000000.000100", technique="T1611"):
    return {
        "type": "block_actions",
        "user": {"id": "U1", "username": "hyewon"},
        "container": {"type": "message", "channel_id": "C1", "message_ts": message_ts},
        "message": {
            "ts": message_ts,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "검수"}},
                {"type": "actions", "elements": []},
            ],
        },
        "response_url": "https://hooks.slack.com/actions/T/1/abc",
        "actions": [{"action_id": action_id, "value": technique}],
    }


def _ok_post():
    return Mock(return_value=Mock(status_code=200))


class DecisionLogicTest(unittest.TestCase):
    def test_approve_updates_message_and_is_not_linked_to_execution(self):
        post = _ok_post()
        result = handle_block_actions(_payload(), store=DecisionStore(), post=post)

        self.assertEqual(result.status, "APPROVED")
        self.assertEqual(result.technique_id, "T1611")
        self.assertEqual(result.decision_key, "C1:1700000000.000100")
        self.assertTrue(result.message_updated)
        self.assertEqual(result.execution, "NOT_LINKED")

        body = post.call_args.kwargs["json"]
        self.assertTrue(body["replace_original"])
        self.assertNotIn("actions", [b["type"] for b in body["blocks"]])  # 버튼이 결과 텍스트로 바뀜
        self.assertIn("승인됨", body["text"])

    def test_reject(self):
        result = handle_block_actions(_payload("reject_chain"), store=DecisionStore(), post=_ok_post())
        self.assertEqual(result.status, "REJECTED")

    def test_duplicate_click_on_same_message_is_ignored(self):
        store, post = DecisionStore(), _ok_post()
        first = handle_block_actions(_payload("approve_chain"), store=store, post=post)
        second = handle_block_actions(_payload("reject_chain"), store=store, post=post)  # 다른 사람이 늦게 반려 클릭
        retry = handle_block_actions(_payload("approve_chain"), store=store, post=post)  # Slack 재전송

        self.assertEqual(first.status, "APPROVED")
        self.assertEqual(second.status, "DUPLICATE")
        self.assertEqual(retry.status, "DUPLICATE")
        self.assertEqual(post.call_count, 1)  # 메시지 갱신은 한 번만

    def test_different_messages_are_independent(self):
        store = DecisionStore()
        a = handle_block_actions(_payload(message_ts="1.1"), store=store, post=_ok_post())
        b = handle_block_actions(_payload(message_ts="2.2"), store=store, post=_ok_post())
        self.assertEqual((a.status, b.status), ("APPROVED", "APPROVED"))

    def test_unknown_action_and_non_block_actions_are_ignored(self):
        post = _ok_post()
        self.assertEqual(handle_block_actions(_payload("other"), store=DecisionStore(), post=post).status, "IGNORED")
        self.assertEqual(handle_block_actions({"type": "view_submission"}, store=DecisionStore(), post=post).status, "IGNORED")
        post.assert_not_called()

    def test_response_url_failure_is_reported_not_raised(self):
        import requests

        post = Mock(side_effect=requests.ConnectionError("down"))
        result = handle_block_actions(_payload(), store=DecisionStore(), post=post)
        self.assertEqual(result.status, "APPROVED")
        self.assertFalse(result.message_updated)

    def test_store_evicts_oldest(self):
        store = DecisionStore(max_size=2)
        for key in ("a", "b", "c"):
            store.claim(key, "APPROVED")
        self.assertIsNone(store.claim("a", "APPROVED"))  # 밀려나서 다시 선점 가능
        self.assertEqual(store.claim("c", "REJECTED"), "APPROVED")


class AppTokenConfigTest(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.pop("SLACK_APP_TOKEN", None)

    def tearDown(self):
        os.environ.pop("SLACK_APP_TOKEN", None)
        if self._old is not None:
            os.environ["SLACK_APP_TOKEN"] = self._old

    def test_missing(self):
        with self.assertRaises(RuntimeError):
            config.get_slack_app_token()

    def test_bot_token_is_rejected_without_leaking_value(self):
        os.environ["SLACK_APP_TOKEN"] = "xoxb-secret-value"
        with self.assertRaises(RuntimeError) as ctx:
            config.get_slack_app_token()
        self.assertNotIn("secret-value", str(ctx.exception))

    def test_valid(self):
        os.environ["SLACK_APP_TOKEN"] = "xapp-1-abc"
        self.assertEqual(config.get_slack_app_token(), "xapp-1-abc")


try:
    import slack_sdk  # noqa: F401

    HAS_SLACK_SDK = True
except ModuleNotFoundError:
    HAS_SLACK_SDK = False


@unittest.skipUnless(HAS_SLACK_SDK, "slack_sdk 미설치")
class SocketListenerTest(unittest.TestCase):
    def _req(self, req_type="interactive", payload=None):
        return types.SimpleNamespace(envelope_id="env-1", type=req_type, payload=payload, retry_attempt=None)

    def test_ack_is_sent_before_processing(self):
        from purplebpf.offensive.review import slack_socket

        order = []
        client = Mock()
        client.send_socket_mode_response.side_effect = lambda resp: order.append(("ack", resp.envelope_id))

        def handler(payload, store):
            order.append(("handle", payload["actions"][0]["action_id"]))
            return decision.DecisionResult("APPROVED", "T1611", "C1:1", "hyewon", True)

        slack_socket.build_listener(handler=handler)(client, self._req(payload=_payload()))
        self.assertEqual(order, [("ack", "env-1"), ("handle", "approve_chain")])

    def test_non_interactive_envelope_is_acked_but_not_handled(self):
        from purplebpf.offensive.review import slack_socket

        client, handler = Mock(), Mock()
        slack_socket.build_listener(handler=handler)(client, self._req("events_api", {"event": {}}))
        client.send_socket_mode_response.assert_called_once()
        handler.assert_not_called()

    def test_handler_exception_does_not_crash_listener(self):
        from purplebpf.offensive.review import slack_socket

        client = Mock()
        handler = Mock(side_effect=ValueError("boom"))
        slack_socket.build_listener(handler=handler)(client, self._req(payload=_payload()))
        client.send_socket_mode_response.assert_called_once()

    def test_connect_retries_network_errors_then_succeeds(self):
        from purplebpf.offensive.review import slack_socket

        client = Mock()
        client.connect.side_effect = [OSError("net"), OSError("net"), None]
        sleeps = []
        slack_socket.connect_with_retry(client, max_attempts=5, sleep=sleeps.append)
        self.assertEqual(client.connect.call_count, 3)
        self.assertEqual(sleeps, [2, 4])

    def test_connect_fails_fast_on_auth_error(self):
        from slack_sdk.errors import SlackApiError

        from purplebpf.offensive.review import slack_socket

        client = Mock()
        client.connect.side_effect = SlackApiError("bad", {"ok": False, "error": "invalid_auth"})
        with self.assertRaises(RuntimeError):
            slack_socket.connect_with_retry(client, max_attempts=5, sleep=lambda s: None)
        self.assertEqual(client.connect.call_count, 1)

    def test_connect_gives_up_after_max_attempts(self):
        from purplebpf.offensive.review import slack_socket

        client = Mock()
        client.connect.side_effect = OSError("net")
        with self.assertRaises(RuntimeError):
            slack_socket.connect_with_retry(client, max_attempts=3, sleep=lambda s: None)
        self.assertEqual(client.connect.call_count, 3)


try:
    import fastapi  # noqa: F401

    HAS_FASTAPI = True
except ModuleNotFoundError:
    HAS_FASTAPI = False


@unittest.skipUnless(HAS_FASTAPI, "fastapi 미설치")
class HttpFallbackTest(unittest.TestCase):
    def test_signed_request_is_acked_and_handled_in_background(self):
        import hashlib
        import hmac
        import json
        import time
        from unittest.mock import patch
        from urllib.parse import urlencode

        from fastapi.testclient import TestClient

        from purplebpf.offensive.review import slack_callback

        os.environ["SLACK_SIGNING_SECRET"] = "test-secret"
        body = urlencode({"payload": json.dumps(_payload())})
        ts = str(int(time.time()))
        sig = "v0=" + hmac.new(b"test-secret", f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()

        with patch.object(slack_callback, "handle_block_actions") as handler:
            response = TestClient(slack_callback.app).post(
                "/slack/interactions",
                content=body,
                headers={
                    "X-Slack-Signature": sig,
                    "X-Slack-Request-Timestamp": ts,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
        self.assertEqual(response.status_code, 200)
        handler.assert_called_once()

    def test_bad_signature_is_rejected(self):
        import time

        from fastapi.testclient import TestClient

        from purplebpf.offensive.review import slack_callback

        os.environ["SLACK_SIGNING_SECRET"] = "test-secret"
        response = TestClient(slack_callback.app).post(
            "/slack/interactions",
            content="payload=%7B%7D",
            headers={"X-Slack-Signature": "v0=bad", "X-Slack-Request-Timestamp": str(int(time.time()))},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
