import json
import sys
import types
import unittest
from unittest.mock import Mock, patch


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


_install_import_stub(
    "docker",
    from_env=Mock(),
    errors=types.SimpleNamespace(NotFound=type("NotFound", (Exception,), {})),
)
_install_import_stub(
    "sqlalchemy", Engine=object, create_engine=Mock(), text=lambda statement: statement
)
_install_import_stub("dotenv", load_dotenv=Mock())
_install_import_stub("neo4j", Driver=object, GraphDatabase=Mock())

from purplebpf.offensive.executor import executor
from purplebpf.offensive.review import slack_notify


CHAIN = {
    "technique_id": "T1552.005",
    "goal": "Read cloud instance metadata.",
    "steps": [
        {
            "order": 1,
            "command": "curl http://169.254.169.254/latest/meta-data/",
            "purpose": "Read metadata.",
        }
    ],
}

FIRST_REVIEW = {
    "verdict": "REVIEW",
    "checks": {
        "ordering": {
            "passed": False,
            "issues": ["A required predecessor could not be confirmed."],
        }
    },
    "reasons": ["순서 검사 위반"],
}

VALIDATOR_REVIEW = {
    "level1": {"status": "PASS"},
    "level2": {
        "status": "REVIEW",
        "errors": [
            {
                "code": "UNSUPPORTED_COMMAND",
                "step": 1,
                "command": CHAIN["steps"][0]["command"],
            }
        ],
    },
    "level3": {"status": "PASS", "errors": []},
    "final": {"status": "PASS", "reason": "LEVEL3_CORE_MATCH"},
}


def gate(decision, validation=None):
    reasons = {
        "REVIEW": "VALIDATION_REVIEW",
        "FAIL": "VALIDATION_REJECTED",
        "ERROR": "VALIDATOR_ERROR",
        "PASS": "VALIDATION_PASSED",
    }
    result = {"decision": decision, "reason": reasons[decision]}
    if validation is not None:
        result["validation"] = validation
    if decision == "ERROR":
        result["error"] = "validator unavailable"
    return result


class ExecutorReviewNotificationTests(unittest.TestCase):
    def _cli_modules(self, filter_result):
        filter_module = types.ModuleType("purplebpf.offensive.filter.first_filter")
        filter_module.filter_chain = Mock(return_value=filter_result)
        generator_module = types.ModuleType("purplebpf.offensive.generation.generator")
        generator_module.generate_chain = Mock(return_value=CHAIN)
        return {
            "purplebpf.offensive.filter.first_filter": filter_module,
            "purplebpf.offensive.generation.generator": generator_module,
        }

    def test_first_filter_review_notifies_once_without_execution(self):
        modules = self._cli_modules(FIRST_REVIEW)
        notification = {"type": "SLACK", "status": "SENT"}
        with patch.dict(sys.modules, modules), patch.object(
            executor, "_notify_scenario_review", return_value=notification
        ) as notify, patch.object(executor, "execute_chain") as execute, patch(
            "builtins.print"
        ) as output:
            exit_code = executor.main([])

        result = json.loads(output.call_args.args[0])
        notify.assert_called_once_with(CHAIN, "FIRST_FILTER", FIRST_REVIEW)
        execute.assert_not_called()
        self.assertEqual(exit_code, executor.EXIT_REVIEW)
        self.assertEqual(result["decision"], "REVIEW")
        self.assertEqual(result["notification"], notification)

    def test_rule_validator_review_notifies_once_before_docker(self):
        notification = {"type": "SLACK", "status": "SENT"}
        with patch.object(
            executor, "_validate_execution_gate", return_value=gate("REVIEW", VALIDATOR_REVIEW)
        ), patch.object(
            executor, "_notify_scenario_review", return_value=notification
        ) as notify, patch.object(executor.docker, "from_env") as from_env:
            result = executor.execute_chain(CHAIN)

        notify.assert_called_once_with(CHAIN, "RULE_VALIDATOR", VALIDATOR_REVIEW)
        from_env.assert_not_called()
        self.assertEqual(result["decision"], "REVIEW")
        self.assertEqual(result["notification"], notification)

    def test_level2_review_and_level3_pass_notifies_and_blocks(self):
        module = types.ModuleType("purplebpf.offensive.validator.main")
        module.validate_scenario_pipeline = Mock(return_value=VALIDATOR_REVIEW)
        with patch.dict(
            sys.modules, {"purplebpf.offensive.validator.main": module}
        ), patch.object(executor, "_notify_scenario_review") as notify, patch.object(
            executor.docker, "from_env"
        ) as from_env:
            result = executor.execute_chain(CHAIN)

        self.assertEqual(result["decision"], "REVIEW")
        notify.assert_called_once_with(CHAIN, "RULE_VALIDATOR", VALIDATOR_REVIEW)
        from_env.assert_not_called()

    def test_pass_does_not_notify_and_uses_execution_path(self):
        container = Mock(short_id="container-id")
        docker_client = Mock()
        docker_client.containers.run.return_value = container
        with patch.object(
            executor, "_validate_execution_gate", return_value=gate("PASS")
        ), patch.object(executor, "_notify_scenario_review") as notify, patch.object(
            executor.docker, "from_env", return_value=docker_client
        ), patch.object(executor, "_run_step", return_value=(0, "ok")), patch.object(
            executor, "_insert_execution_log", return_value={"success": True}
        ):
            result = executor.execute_chain(CHAIN)

        notify.assert_not_called()
        docker_client.containers.run.assert_called_once()
        self.assertTrue(result["success"])

    def test_first_filter_reject_does_not_notify(self):
        rejection = {"verdict": "REJECT", "checks": {}, "reasons": ["invalid"]}
        modules = self._cli_modules(rejection)
        with patch.dict(sys.modules, modules), patch.object(
            executor, "_notify_scenario_review"
        ) as notify, patch.object(executor, "execute_chain") as execute, patch(
            "builtins.print"
        ):
            exit_code = executor.main([])

        self.assertEqual(exit_code, executor.EXIT_REJECTED)
        notify.assert_not_called()
        execute.assert_not_called()

    def test_validator_fail_does_not_notify_or_create_docker(self):
        with patch.object(
            executor, "_validate_execution_gate", return_value=gate("FAIL", {})
        ), patch.object(executor, "_notify_scenario_review") as notify, patch.object(
            executor.docker, "from_env"
        ) as from_env:
            result = executor.execute_chain(CHAIN)

        self.assertEqual(result["decision"], "FAIL")
        notify.assert_not_called()
        from_env.assert_not_called()

    def test_validator_error_does_not_notify_or_create_docker(self):
        with patch.object(
            executor, "_validate_execution_gate", return_value=gate("ERROR")
        ), patch.object(executor, "_notify_scenario_review") as notify, patch.object(
            executor.docker, "from_env"
        ) as from_env:
            result = executor.execute_chain(CHAIN)

        self.assertEqual(result["decision"], "ERROR")
        notify.assert_not_called()
        from_env.assert_not_called()

    def test_slack_send_failure_keeps_review_decision(self):
        with patch.object(slack_notify, "notify_review", return_value=False):
            notification = slack_notify.notify_scenario_review(
                CHAIN, "RULE_VALIDATOR", VALIDATOR_REVIEW
            )
        with patch.object(
            executor, "_validate_execution_gate", return_value=gate("REVIEW", VALIDATOR_REVIEW)
        ), patch.object(
            executor, "_notify_scenario_review", return_value=notification
        ), patch.object(executor.docker, "from_env") as from_env:
            result = executor.execute_chain(CHAIN)

        self.assertEqual(notification["status"], "FAILED")
        self.assertEqual(result["decision"], "REVIEW")
        self.assertEqual(result["notification"]["status"], "FAILED")
        from_env.assert_not_called()

    def test_missing_slack_configuration_is_not_configured(self):
        with patch.object(
            slack_notify,
            "notify_review",
            side_effect=RuntimeError("SLACK_WEBHOOK_URL 환경변수가 설정되어 있지 않다."),
        ):
            notification = slack_notify.notify_scenario_review(
                CHAIN, "RULE_VALIDATOR", VALIDATOR_REVIEW
            )

        self.assertEqual(notification, {"type": "SLACK", "status": "NOT_CONFIGURED"})

    def test_first_filter_pass_validator_review_sends_only_validator_notification(self):
        modules = self._cli_modules({"verdict": "PASS", "checks": {}, "reasons": []})
        notification = {"type": "SLACK", "status": "SENT"}
        with patch.dict(sys.modules, modules), patch.object(
            executor, "_validate_execution_gate", return_value=gate("REVIEW", VALIDATOR_REVIEW)
        ), patch.object(
            executor, "_notify_scenario_review", return_value=notification
        ) as notify, patch.object(executor.docker, "from_env") as from_env, patch(
            "builtins.print"
        ):
            exit_code = executor.main([])

        self.assertEqual(exit_code, executor.EXIT_REVIEW)
        notify.assert_called_once_with(CHAIN, "RULE_VALIDATOR", VALIDATOR_REVIEW)
        from_env.assert_not_called()

    def test_message_contains_review_context_without_webhook_data(self):
        with patch.object(slack_notify, "notify_review", return_value=True) as send:
            notification = slack_notify.notify_scenario_review(
                CHAIN, "RULE_VALIDATOR", VALIDATOR_REVIEW
            )

        sent_chain, verdict = send.call_args.args
        blocks = slack_notify._build_blocks(sent_chain, verdict)
        rendered = "\n".join(
            block.get("text", {}).get("text", "") for block in blocks
        )
        self.assertEqual(notification["status"], "SENT")
        self.assertIn(CHAIN["technique_id"], json.dumps(blocks))
        self.assertIn("RULE_VALIDATOR", rendered)
        self.assertIn("LEVEL2", rendered)
        self.assertIn("UNSUPPORTED_COMMAND", rendered)
        self.assertIn("Blocked before Docker execution", rendered)
        self.assertNotIn("SLACK_WEBHOOK_URL", rendered)
        self.assertNotIn("https://hooks.slack.com", rendered)


if __name__ == "__main__":
    unittest.main()
