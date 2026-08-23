import sys
import types
import unittest
from unittest.mock import ANY, Mock, patch


try:
    import docker  # noqa: F401
except ModuleNotFoundError:
    docker_stub = types.ModuleType("docker")
    docker_stub.from_env = Mock()
    docker_stub.errors = types.SimpleNamespace(NotFound=type("NotFound", (Exception,), {}))
    sys.modules["docker"] = docker_stub

try:
    import sqlalchemy  # noqa: F401
except ModuleNotFoundError:
    sqlalchemy_stub = types.ModuleType("sqlalchemy")
    sqlalchemy_stub.Engine = object
    sqlalchemy_stub.create_engine = Mock()
    sqlalchemy_stub.text = lambda statement: statement
    sys.modules["sqlalchemy"] = sqlalchemy_stub

try:
    import dotenv  # noqa: F401
except ModuleNotFoundError:
    dotenv_stub = types.ModuleType("dotenv")
    dotenv_stub.load_dotenv = Mock()
    sys.modules["dotenv"] = dotenv_stub

try:
    import neo4j  # noqa: F401
except ModuleNotFoundError:
    neo4j_stub = types.ModuleType("neo4j")
    neo4j_stub.Driver = object
    neo4j_stub.GraphDatabase = Mock()
    sys.modules["neo4j"] = neo4j_stub

from purplebpf.offensive.executor import executor


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


def validation_result(level1, level2, level3, final):
    return {
        "scenario": {"technique_id": CHAIN["technique_id"], "step_count": 1},
        "level1": None if level1 is None else {"status": level1},
        "level2": None if level2 is None else {"status": level2},
        "level3": None if level3 is None else {"status": level3},
        "final": None if final is None else {"status": final},
    }


class ExecutorValidationGateTests(unittest.TestCase):
    def _validator_module(self, *, result=None, side_effect=None):
        validator = Mock(return_value=result, side_effect=side_effect)
        module = types.ModuleType("purplebpf.offensive.validator.main")
        module.validate_scenario_pipeline = validator
        return module, validator

    def _execute_with_blocked_dependencies(self, validator_module, *, allow_review=False):
        docker_client = Mock()
        with patch.dict(
            sys.modules,
            {"purplebpf.offensive.validator.main": validator_module},
        ), patch.object(executor.docker, "from_env", return_value=docker_client) as from_env, patch.object(
            executor, "_run_step"
        ) as run_step, patch.object(executor, "_insert_execution_log") as insert_log:
            result = executor.execute_chain(CHAIN, allow_review=allow_review)
        return result, from_env, docker_client.containers.run, run_step, insert_log

    def _assert_blocked(self, validation, expected_decision, expected_reason):
        module, validator = self._validator_module(result=validation)
        result, from_env, container_run, run_step, insert_log = (
            self._execute_with_blocked_dependencies(module)
        )

        validator.assert_called_once_with(CHAIN)
        self.assertEqual(result["decision"], expected_decision)
        self.assertEqual(result["reason"], expected_reason)
        self.assertFalse(result["success"])
        self.assertEqual(result["step_results"], [])
        from_env.assert_not_called()
        container_run.assert_not_called()
        run_step.assert_not_called()
        if expected_decision in ("REVIEW", "FAIL"):
            # REVIEW/REJECT는 human-in-the-loop으로 실행만 막힐 뿐, round_id가
            # 밀리지 않도록 execution_log에는 success=false로 남는다.
            insert_log.assert_called_once_with(
                round_id=1,
                chain_id=ANY,
                technique=CHAIN["technique_id"],
                channel=executor.CHANNEL,
                success=False,
                started_at=ANY,
                finished_at=ANY,
                container_id=executor.BLOCKED_CONTAINER_ID,
            )
        else:
            # ERROR(검증기 자체 오류/이상 결과)는 방어 시스템의 정상 판정이
            # 아니므로 execution_log에 남기지 않는다.
            insert_log.assert_not_called()
        return result

    def test_all_levels_pass_enters_existing_execution_path(self):
        validation = validation_result("PASS", "PASS", "PASS", "PASS")
        module, validator = self._validator_module(result=validation)
        container = Mock(short_id="container-id")
        docker_client = Mock()
        docker_client.containers.run.return_value = container
        execution_record = {"run_id": 7, "success": True}

        with patch.dict(
            sys.modules,
            {"purplebpf.offensive.validator.main": module},
        ), patch.object(executor.docker, "from_env", return_value=docker_client) as from_env, patch.object(
            executor, "_run_step", return_value=(0, "ok")
        ) as run_step, patch.object(
            executor, "_insert_execution_log", return_value=execution_record
        ) as insert_log:
            result = executor.execute_chain(CHAIN)

        validator.assert_called_once_with(CHAIN)
        from_env.assert_called_once_with()
        docker_client.containers.run.assert_called_once()
        container_options = docker_client.containers.run.call_args.kwargs
        self.assertIs(container_options["privileged"], False)
        self.assertEqual(container_options["network_mode"], "bridge")
        self.assertIsNone(container_options["pid_mode"])
        self.assertEqual(container_options["cap_add"], [])
        self.assertEqual(container_options["security_opt"], ["no-new-privileges"])
        self.assertNotIn("volumes", container_options)
        run_step.assert_called_once_with(container, CHAIN["steps"][0]["command"])
        insert_log.assert_called_once()
        container.remove.assert_called_once_with(force=True)
        self.assertEqual(result["run_id"], 7)
        self.assertEqual(result["step_results"][0]["exit_code"], 0)
        self.assertEqual(result["validation_status"], "PASS")
        self.assertTrue(result["execution_allowed"])
        self.assertEqual(result["execution_policy"], "STANDARD")
        self.assertFalse(result["review_override"])

    def test_execution_policy_matrix_is_fail_closed(self):
        cases = (
            (("PASS",), False, "PASS", True, False),
            (("PASS",), True, "PASS", True, False),
            (("REVIEW",), False, "REVIEW", False, False),
            (("REVIEW",), True, "REVIEW", True, True),
            (("REJECT",), True, "REJECT", False, False),
            (("FAIL",), True, "FAIL", False, False),
            (("ERROR",), True, "ERROR", False, False),
            (("UNKNOWN",), True, "ERROR", False, False),
            (("REVIEW", "REJECT"), True, "REJECT", False, False),
        )
        for statuses, allow_review, status, allowed, override in cases:
            with self.subTest(statuses=statuses, allow_review=allow_review):
                result = executor.decide_execution(statuses, allow_review)
                self.assertEqual(result["validation_status"], status)
                self.assertEqual(result["execution_allowed"], allowed)
                self.assertEqual(result["review_override"], override)
                expected_policy = "DEMO_ALLOW_REVIEW" if override else "STANDARD"
                self.assertEqual(result["execution_policy"], expected_policy)

    def test_level1_failure_blocks_direct_execution(self):
        result = self._assert_blocked(
            validation_result("FAIL", None, None, "REJECT"),
            "FAIL",
            "VALIDATION_REJECTED",
        )
        self.assertEqual(result["status"], "SKIPPED")

    def test_allow_review_does_not_override_direct_failure(self):
        validation = validation_result("FAIL", None, None, "REJECT")
        module, validator = self._validator_module(result=validation)
        result, from_env, container_run, run_step, insert_log = (
            self._execute_with_blocked_dependencies(module, allow_review=True)
        )

        validator.assert_called_once_with(CHAIN)
        self.assertEqual(result["decision"], "FAIL")
        self.assertFalse(result["execution_allowed"])
        self.assertFalse(result["review_override"])
        from_env.assert_not_called()
        container_run.assert_not_called()
        run_step.assert_not_called()
        insert_log.assert_called_once_with(
            round_id=1,
            chain_id=ANY,
            technique=CHAIN["technique_id"],
            channel=executor.CHANNEL,
            success=False,
            started_at=ANY,
            finished_at=ANY,
            container_id=executor.BLOCKED_CONTAINER_ID,
        )

    def test_execute_chain_direct_call_cannot_bypass_gate(self):
        self._assert_blocked(
            validation_result("PASS", "REVIEW", "REVIEW", "REVIEW"),
            "REVIEW",
            "VALIDATION_REVIEW",
        )

    def test_execute_chain_direct_call_allows_review_only_when_explicit(self):
        validation = validation_result("PASS", "REVIEW", "PASS", "REVIEW")
        module, validator = self._validator_module(result=validation)
        container = Mock(short_id="container-id")
        docker_client = Mock()
        docker_client.containers.run.return_value = container

        with patch.dict(
            sys.modules,
            {"purplebpf.offensive.validator.main": module},
        ), patch.object(
            executor, "_notify_scenario_review", return_value={"status": "SENT"}
        ) as notify, patch.object(
            executor.docker, "from_env", return_value=docker_client
        ) as from_env, patch.object(
            executor, "_run_step", return_value=(0, "ok")
        ), patch.object(
            executor, "_insert_execution_log", return_value={"run_id": 8, "success": True}
        ):
            result = executor.execute_chain(CHAIN, allow_review=True)

        validator.assert_called_once_with(CHAIN)
        notify.assert_called_once_with(CHAIN, "RULE_VALIDATOR", validation)
        from_env.assert_called_once_with()
        docker_client.containers.run.assert_called_once()
        self.assertEqual(result["validation_status"], "REVIEW")
        self.assertTrue(result["execution_allowed"])
        self.assertEqual(result["execution_policy"], "DEMO_ALLOW_REVIEW")
        self.assertTrue(result["review_override"])

    def test_level2_reject_blocks_execution(self):
        self._assert_blocked(
            validation_result("PASS", "REJECT", None, "REJECT"),
            "FAIL",
            "VALIDATION_REJECTED",
        )

    def test_level2_review_is_not_overridden_by_level3_pass(self):
        self._assert_blocked(
            validation_result("PASS", "REVIEW", "PASS", "PASS"),
            "REVIEW",
            "VALIDATION_REVIEW",
        )

    def test_level3_review_blocks_execution(self):
        self._assert_blocked(
            validation_result("PASS", "PASS", "REVIEW", "REVIEW"),
            "REVIEW",
            "VALIDATION_REVIEW",
        )

    def test_level3_reject_blocks_execution(self):
        self._assert_blocked(
            validation_result("PASS", "PASS", "REJECT", "REJECT"),
            "FAIL",
            "VALIDATION_REJECTED",
        )

    def test_validator_exception_fails_closed(self):
        module, validator = self._validator_module(
            side_effect=RuntimeError("validator unavailable")
        )
        result, from_env, container_run, run_step, insert_log = (
            self._execute_with_blocked_dependencies(module)
        )

        validator.assert_called_once_with(CHAIN)
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["decision"], "ERROR")
        self.assertEqual(result["reason"], "VALIDATOR_ERROR")
        self.assertIn("RuntimeError", result["error"])
        from_env.assert_not_called()
        container_run.assert_not_called()
        run_step.assert_not_called()
        insert_log.assert_not_called()

    def test_unknown_or_missing_status_fails_closed(self):
        result = self._assert_blocked(
            validation_result("PASS", "UNKNOWN", None, "PASS"),
            "ERROR",
            "VALIDATION_RESULT_INVALID",
        )
        self.assertEqual(result["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
