import subprocess


def check_shell_syntax(command: str) -> dict:
    result = subprocess.run(
        ["shellcheck", "-s", "bash", "-"],
        input=command,
        text=True,
        capture_output=True
    )

    return {
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "diagnostics": result.stdout.strip()
    }
