import json
import sys
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
from purplebpf.offensive.review import slack_notify


FIXTURES = Path(__file__).parent / "fixtures" / "scenarios"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def validation(level1="PASS", level2="PASS", level3="PASS", final="PASS"):
    level2_errors = []
    if level2 == "REVIEW":
        level2_errors = [
            {
                "code": "UNSUPPORTED_COMMAND",
                "step": 1,
                "command": load_fixture("validator_review.json")["steps"][0]["command"],
            }
        ]
    return {
        "scenario": {"technique_id": "T1552.005", "step_count": 1},
        "level1": None if level1 is None else {"status": level1},
        "level2": None if level2 is None else {"status": level2, "errors": level2_errors},
        "level3": None if level3 is None else {"status": level3, "errors": []},
        "final": {"status": final, "reason": f"E2E_{final}"},
    }


class OffensivePipelineE2ETests(unittest.TestCase):
    def _modules(self, validator_result, *, generated=None, validator_error=None, generation_error=None):
        validator_function = Mock(return_value=validator_result, side_effect=validator_error)
        validator_module = types.ModuleType("purplebpf.offensive.validator.main")
        validator_module.validate_scenario_pipeline = validator_function

        generator_function = Mock(return_value=generated, side_effect=generation_error)
        generator_module = types.ModuleType("purplebpf.offensive.generation.generator")
        generator_module.generate_chain = generator_function
        return {
            "purplebpf.offensive.validator.main": validator_module,
            "purplebpf.offensive.generation.generator": generator_module,
        }, validator_function, generator_function

    def _run_cli(
        self,
        argv,
        *,
        validator_result=None,
        generated=None,
        validator_error=None,
        generation_error=None,
        docker_error=None,
    ):
        modules, validator_function, generator_function = self._modules(
            validator_result,
            generated=generated,
            validator_error=validator_error,
            generation_error=generation_error,
        )
        container = Mock(short_id="e2e-container")
        docker_client = Mock()
        if docker_error is None:
            docker_client.containers.run.return_value = container
        else:
            docker_client.containers.run.side_effect = docker_error

        with patch.dict(sys.modules, modules), patch.object(
            executor.docker, "from_env", return_value=docker_client
        ) as from_env, patch.object(
            executor, "_run_step", return_value=(0, "ok")
        ) as run_step, patch.object(
            executor,
            "_insert_execution_log",
            return_value={"run_id": 101, "success": True},
        ) as insert_log, patch.object(
            slack_notify, "notify_review", return_value=True
        ) as slack, patch("builtins.print") as output:
            exit_code = executor.main(argv)

        result = json.loads(output.call_args.args[0]) if output.called else None
        return {
            "exit_code": exit_code,
            "result": result,
            "validator": validator_function,
            "generator": generator_function,
            "from_env": from_env,
            "container_run": docker_client.containers.run,
            "run_step": run_step,
            "insert_log": insert_log,
            "slack": slack,
        }

    def test_e2e_001_chain_file_all_pass_executes_once(self):
        scenario = load_fixture("pass.json")
        run = self._run_cli(
            ["--chain-file", str(FIXTURES / "pass.json")],
            validator_result=validation(),
        )

        self.assertEqual(run["exit_code"], executor.EXIT_SUCCESS)
        run["validator"].assert_called_once_with(scenario)
        run["from_env"].assert_called_once_with()
        run["container_run"].assert_called_once()
        run["run_step"].assert_called_once()
        run["insert_log"].assert_called_once()
        run["slack"].assert_not_called()
        self.assertEqual(run["result"]["status"], "EXECUTED")

    def test_e2e_002_first_filter_review_stops_before_validator(self):
        run = self._run_cli(
            ["--chain-file", str(FIXTURES / "first_filter_review.json")],
            validator_result=validation(),
        )

        self.assertEqual(run["exit_code"], executor.EXIT_REVIEW)
        self.assertEqual(run["result"]["blocked_by"], "FIRST_FILTER")
        self.assertEqual(run["result"]["notification"]["status"], "SENT")
        run["validator"].assert_not_called()
        run["from_env"].assert_not_called()
        run["slack"].assert_called_once()

    def test_e2e_003_level2_review_is_not_overridden_by_final_pass(self):
        scenario = load_fixture("validator_review.json")
        review = validation(level2="REVIEW", level3="PASS", final="PASS")
        run = self._run_cli(
            ["--chain-file", str(FIXTURES / "validator_review.json")],
            validator_result=review,
        )

        self.assertEqual(run["exit_code"], executor.EXIT_REVIEW)
        run["validator"].assert_called_once_with(scenario)
        run["from_env"].assert_not_called()
        run["run_step"].assert_not_called()
        run["insert_log"].assert_not_called()
        run["slack"].assert_called_once()
        self.assertEqual(run["result"]["blocked_by"], "RULE_VALIDATOR")
        self.assertEqual(run["result"]["notification"]["status"], "SENT")

    def test_e2e_004_validator_reject_blocks_without_slack_or_db(self):
        rejection = validation(level2="REJECT", level3=None, final="REJECT")
        run = self._run_cli(
            ["--chain-file", str(FIXTURES / "pass.json")],
            validator_result=rejection,
        )

        self.assertEqual(run["exit_code"], executor.EXIT_REJECTED)
        self.assertEqual(run["result"]["decision"], "FAIL")
        run["from_env"].assert_not_called()
        run["run_step"].assert_not_called()
        run["insert_log"].assert_not_called()
        run["slack"].assert_not_called()

    def test_e2e_005_validator_exception_is_fail_closed(self):
        run = self._run_cli(
            ["--chain-file", str(FIXTURES / "pass.json")],
            validator_error=RuntimeError("validator unavailable"),
        )

        self.assertEqual(run["exit_code"], executor.EXIT_SYSTEM_ERROR)
        self.assertEqual(run["result"]["reason"], "VALIDATOR_ERROR")
        run["from_env"].assert_not_called()
        run["run_step"].assert_not_called()
        run["slack"].assert_not_called()

    def test_e2e_006_gemma_mock_pass_uses_the_same_execution_policy(self):
        scenario = load_fixture("pass.json")
        run = self._run_cli(
            [scenario["technique_id"]],
            generated=scenario,
            validator_result=validation(),
        )

        self.assertEqual(run["exit_code"], executor.EXIT_SUCCESS)
        run["generator"].assert_called_once_with(scenario["technique_id"])
        run["validator"].assert_called_once_with(scenario)
        run["container_run"].assert_called_once()
        run["slack"].assert_not_called()

    def test_first_filter_reject_stops_before_validator(self):
        run = self._run_cli(
            ["--chain-file", str(FIXTURES / "reject.json")],
            validator_result=validation(),
        )

        self.assertEqual(run["exit_code"], executor.EXIT_REJECTED)
        self.assertEqual(run["result"]["blocked_by"], "FIRST_FILTER")
        run["validator"].assert_not_called()
        run["from_env"].assert_not_called()
        run["slack"].assert_not_called()

    def test_invalid_chain_file_stops_before_all_pipeline_stages(self):
        run = self._run_cli(
            ["--chain-file", str(FIXTURES / "invalid.json")],
            validator_result=validation(),
        )

        self.assertEqual(run["exit_code"], executor.EXIT_INVALID_INPUT)
        self.assertEqual(run["result"]["reason"], "SCENARIO_INPUT_ERROR")
        run["validator"].assert_not_called()
        run["from_env"].assert_not_called()
        run["slack"].assert_not_called()

    def test_docker_creation_error_is_an_executor_system_error(self):
        run = self._run_cli(
            ["--chain-file", str(FIXTURES / "pass.json")],
            validator_result=validation(),
            docker_error=RuntimeError("docker unavailable"),
        )

        self.assertEqual(run["exit_code"], executor.EXIT_SYSTEM_ERROR)
        self.assertEqual(run["result"]["reason"], "EXECUTOR_ERROR")
        run["validator"].assert_called_once()
        run["container_run"].assert_called_once()
        run["run_step"].assert_not_called()
        run["insert_log"].assert_not_called()
        run["slack"].assert_not_called()

    def test_gemma_review_and_reject_follow_first_filter_policy(self):
        for fixture, expected_code, expected_decision, slack_count in (
            ("first_filter_review.json", executor.EXIT_REVIEW, "REVIEW", 1),
            ("reject.json", executor.EXIT_REJECTED, "FAIL", 0),
        ):
            with self.subTest(fixture=fixture):
                scenario = load_fixture(fixture)
                run = self._run_cli(
                    [scenario["technique_id"]],
                    generated=scenario,
                    validator_result=validation(),
                )
                self.assertEqual(run["exit_code"], expected_code)
                self.assertEqual(run["result"]["decision"], expected_decision)
                run["validator"].assert_not_called()
                run["from_env"].assert_not_called()
                self.assertEqual(run["slack"].call_count, slack_count)

    def test_gemma_invalid_shapes_and_generation_error_fail_closed(self):
        cases = (
            ([], None, executor.EXIT_INVALID_INPUT),
            (load_fixture("missing_fields.json"), None, executor.EXIT_REJECTED),
            (None, RuntimeError("generation unavailable"), executor.EXIT_SYSTEM_ERROR),
        )
        for generated, error, expected_code in cases:
            with self.subTest(generated=generated, error=error):
                run = self._run_cli(
                    [],
                    generated=generated,
                    generation_error=error,
                    validator_result=validation(),
                )
                self.assertEqual(run["exit_code"], expected_code)
                run["validator"].assert_not_called()
                run["from_env"].assert_not_called()

    def test_dagster_and_demo_route_through_executor_cli(self):
        root = Path(__file__).parents[1]
        dagster_source = (root / "orchestration/assets/coverage_loop.py").read_text(
            encoding="utf-8"
        )
        demo_source = (root / "demo/run_cycle.sh").read_text(encoding="utf-8")

        module_path = "purplebpf.offensive.executor.executor"
        self.assertIn(f"python3 -m {module_path}", dagster_source)
        self.assertIn(f"-m {module_path}", demo_source)
        self.assertIn("--chain-file", demo_source)
        self.assertIn("EXECUTOR_RC=$?", demo_source)
        self.assertIn("exit_code=%d", demo_source)


if __name__ == "__main__":
    unittest.main()
