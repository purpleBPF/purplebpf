import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
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

FILTER_PASS = {"verdict": "PASS", "checks": {}, "reasons": []}


class ExecutorCliTests(unittest.TestCase):
    def _modules(self, *, filter_result=FILTER_PASS, generated_chain=CHAIN, generation_error=None):
        filter_function = Mock(return_value=filter_result)
        filter_module = types.ModuleType("purplebpf.offensive.filter.first_filter")
        filter_module.filter_chain = filter_function

        generate_function = Mock(return_value=generated_chain, side_effect=generation_error)
        generator_module = types.ModuleType("purplebpf.offensive.generation.generator")
        generator_module.generate_chain = generate_function
        return {
            "purplebpf.offensive.filter.first_filter": filter_module,
            "purplebpf.offensive.generation.generator": generator_module,
        }, filter_function, generate_function

    def _run(self, argv, *, filter_result=FILTER_PASS, execution_result=None, generation_error=None):
        modules, filter_function, generate_function = self._modules(
            filter_result=filter_result,
            generation_error=generation_error,
        )
        execute_function = Mock(return_value=execution_result)
        with patch.dict(sys.modules, modules), patch.object(
            executor, "execute_chain", execute_function
        ), patch("builtins.print") as output:
            exit_code = executor.main(argv)
        rendered = json.loads(output.call_args.args[0]) if output.called else None
        return exit_code, rendered, filter_function, generate_function, execute_function

    def test_gemma_pass_execution_success_returns_zero(self):
        execution = {"run_id": 1, "success": True, "step_results": [{"exit_code": 0}]}
        exit_code, result, first_filter, generate, execute = self._run(
            ["T1552.005", "--round-id", "9"], execution_result=execution
        )

        self.assertEqual(exit_code, executor.EXIT_SUCCESS)
        generate.assert_called_once_with("T1552.005")
        first_filter.assert_called_once_with(CHAIN)
        execute.assert_called_once_with(CHAIN, round_id=9)
        self.assertEqual(result["status"], "EXECUTED")
        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["step_results"], execution["step_results"])

    def test_chain_file_pass_uses_same_filter_and_execution_flow(self):
        execution = {"run_id": 2, "success": True, "step_results": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            path.write_text(json.dumps(CHAIN), encoding="utf-8")
            exit_code, result, first_filter, generate, execute = self._run(
                ["--chain-file", str(path), "--round-id", "4"],
                execution_result=execution,
            )

        self.assertEqual(exit_code, executor.EXIT_SUCCESS)
        generate.assert_not_called()
        first_filter.assert_called_once_with(CHAIN)
        execute.assert_called_once_with(CHAIN, round_id=4)
        self.assertEqual(result["status"], "EXECUTED")

    def test_first_filter_review_blocks_execution(self):
        verdict = {"verdict": "REVIEW", "checks": {"ordering": {}}, "reasons": ["review"]}
        exit_code, result, _, _, execute = self._run([], filter_result=verdict)

        self.assertEqual(exit_code, executor.EXIT_REVIEW)
        execute.assert_not_called()
        self.assertEqual(result["decision"], "REVIEW")
        self.assertEqual(result["blocked_by"], "FIRST_FILTER")
        self.assertEqual(result["first_filter"], verdict)

    def test_first_filter_reject_blocks_execution(self):
        verdict = {"verdict": "REJECT", "checks": {}, "reasons": ["invalid"]}
        exit_code, result, _, _, execute = self._run([], filter_result=verdict)

        self.assertEqual(exit_code, executor.EXIT_REJECTED)
        execute.assert_not_called()
        self.assertEqual(result["decision"], "FAIL")
        self.assertEqual(result["blocked_by"], "FIRST_FILTER")

    def test_unknown_first_filter_status_fails_closed(self):
        exit_code, result, _, _, execute = self._run(
            [], filter_result={"verdict": "UNKNOWN", "reasons": []}
        )

        self.assertEqual(exit_code, executor.EXIT_SYSTEM_ERROR)
        execute.assert_not_called()
        self.assertEqual(result["decision"], "ERROR")
        self.assertEqual(result["reason"], "FIRST_FILTER_RESULT_INVALID")

    def test_rule_validator_review_returns_three(self):
        execution = {
            "status": "SKIPPED",
            "decision": "REVIEW",
            "success": False,
            "reason": "VALIDATION_REVIEW",
            "step_results": [],
        }
        exit_code, result, _, _, _ = self._run([], execution_result=execution)

        self.assertEqual(exit_code, executor.EXIT_REVIEW)
        self.assertEqual(result["blocked_by"], "RULE_VALIDATOR")

    def test_rule_validator_fail_returns_two(self):
        execution = {
            "status": "SKIPPED",
            "decision": "FAIL",
            "success": False,
            "reason": "VALIDATION_REJECTED",
            "step_results": [],
        }
        exit_code, result, _, _, _ = self._run([], execution_result=execution)

        self.assertEqual(exit_code, executor.EXIT_REJECTED)
        self.assertEqual(result["blocked_by"], "RULE_VALIDATOR")

    def test_rule_validator_error_returns_four(self):
        execution = {
            "status": "ERROR",
            "decision": "ERROR",
            "success": False,
            "reason": "VALIDATOR_ERROR",
            "step_results": [],
        }
        exit_code, result, _, _, _ = self._run([], execution_result=execution)

        self.assertEqual(exit_code, executor.EXIT_SYSTEM_ERROR)
        self.assertEqual(result["blocked_by"], "RULE_VALIDATOR")

    def test_failed_command_after_execution_returns_one(self):
        execution = {
            "run_id": 3,
            "success": False,
            "step_results": [{"order": 1, "exit_code": 1}],
        }
        exit_code, result, _, _, _ = self._run([], execution_result=execution)

        self.assertEqual(exit_code, executor.EXIT_EXECUTION_FAILED)
        self.assertEqual(result["status"], "EXECUTED")
        self.assertEqual(result["decision"], "PASS")
        self.assertFalse(result["success"])

    def test_gemma_generation_error_returns_four_without_execution(self):
        exit_code, result, first_filter, _, execute = self._run(
            [],
            generation_error=RuntimeError("generation unavailable"),
        )

        self.assertEqual(exit_code, executor.EXIT_SYSTEM_ERROR)
        self.assertEqual(result["reason"], "SCENARIO_GENERATION_ERROR")
        first_filter.assert_not_called()
        execute.assert_not_called()

    def test_invalid_chain_file_returns_five_before_filter_or_execution(self):
        modules, first_filter, generate = self._modules()
        execute = Mock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            path.write_text("{", encoding="utf-8")
            with patch.dict(sys.modules, modules), patch.object(
                executor, "execute_chain", execute
            ), patch("builtins.print") as output:
                exit_code = executor.main(["--chain-file", str(path)])

        result = json.loads(output.call_args.args[0])
        self.assertEqual(exit_code, executor.EXIT_INVALID_INPUT)
        self.assertEqual(result["reason"], "SCENARIO_INPUT_ERROR")
        generate.assert_not_called()
        first_filter.assert_not_called()
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
