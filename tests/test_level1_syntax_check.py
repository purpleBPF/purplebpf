import json
import subprocess
import unittest
from unittest.mock import patch

from purplebpf.offensive.validator.levels.level1 import syntax_check


def completed(returncode, diagnostics=None, stderr=""):
    return subprocess.CompletedProcess(
        args=["shellcheck"],
        returncode=returncode,
        stdout=json.dumps(diagnostics or []),
        stderr=stderr,
    )


def diagnostic(code, level):
    return {
        "file": "-",
        "line": 1,
        "endLine": 1,
        "column": 1,
        "endColumn": 2,
        "level": level,
        "code": code,
        "message": "diagnostic",
        "fix": None,
    }


class ShellCheckSeverityTests(unittest.TestCase):
    def run_with(self, result):
        with patch.object(syntax_check.subprocess, "run", return_value=result):
            return syntax_check.check_shell_syntax("echo test")

    def test_no_diagnostics_passes(self):
        result = self.run_with(completed(0))

        self.assertTrue(result["passed"])
        self.assertEqual(result["diagnostic_items"], [])

    def test_info_and_style_pass_and_are_preserved(self):
        for code, level in ((2015, "info"), (2002, "style")):
            with self.subTest(code=code, level=level):
                item = diagnostic(code, level)
                result = self.run_with(completed(1, [item]))

                self.assertTrue(result["passed"])
                self.assertEqual(result["diagnostic_items"], [item])
                self.assertIn(f'"code": {code}', result["diagnostics"])

    def test_error_and_warning_fail(self):
        for code, level in ((1073, "error"), (2155, "warning")):
            with self.subTest(code=code, level=level):
                item = diagnostic(code, level)
                result = self.run_with(completed(1, [item]))

                self.assertFalse(result["passed"])
                self.assertEqual(result["diagnostic_items"], [item])

    def test_abnormal_tool_exit_is_distinct_from_syntax_failure(self):
        result = self.run_with(completed(2, stderr="tool failure"))

        self.assertFalse(result["passed"])
        self.assertEqual(result["diagnostic_items"], [])
        self.assertIn("exited abnormally", result["tool_error"])


if __name__ == "__main__":
    unittest.main()
