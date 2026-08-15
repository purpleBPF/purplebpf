import json
import sys

from checks.syntax_check import check_shell_syntax


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <scenario.json>")
        sys.exit(1)

    scenario_path = sys.argv[1]

    with open(scenario_path, "r", encoding="utf-8") as f:
        scenario = json.load(f)

    results = []
    level_passed = True

    for step in scenario["steps"]:
        command = step["command"]

        result = check_shell_syntax(command)

        if not result["passed"]:
            level_passed = False

        results.append({
            "order": step["order"],
            "command": command,
            "passed": result["passed"],
            "diagnostics": result["diagnostics"]
        })

    output = {
        "level": 1,
        "check": "shell_syntax",
        "status": "PASS" if level_passed else "FAIL",
        "steps": results
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
