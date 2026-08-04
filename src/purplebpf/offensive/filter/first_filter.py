"""GraphRAG 생성 체인의 1차 필터 — 문법·구조·기본 순서를 기계적으로 검사한다.

의미적 공격 유효성 판단(이 체인이 실제로 탈출에 성공하는가 등)은 이 필터의 범위가
아니다. 그건 사람의 2차 검수 몫이다. 이 필터는 명백한 형식 오류를 걸러
사람의 검수 부담을 줄이는 것이 목적이다.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

import yaml

RULES_PATH = Path(__file__).parent / "rules.yaml"
SHELLCHECK_TIMEOUT_SECONDS = 10

# --shell=bash로 해결되지만, 방어적으로 남겨둔다: 실제 문법 오류가 아니라
# 검사 환경/설정에 관한 경고라서 syntax 실패로 취급하지 않는다.
SHELLCHECK_IGNORE_CODES = {"SC2148"}


def filter_chain(chain: dict) -> dict:
    structure_passed, structure_issues = _check_structure(chain)
    syntax_passed, syntax_issues = _check_syntax(chain)
    ordering_passed, ordering_issues = _check_ordering(chain, _load_rules())

    checks = {
        "structure": {"passed": structure_passed, "issues": structure_issues},
        "syntax": {"passed": syntax_passed, "issues": syntax_issues},
        "ordering": {"passed": ordering_passed, "issues": ordering_issues},
    }

    reasons: list[str] = []
    if not structure_passed:
        reasons.append("구조 검사 실패: " + "; ".join(structure_issues))
    if not syntax_passed:
        error_count = sum(1 for issue in syntax_issues if issue.get("level") == "error")
        reasons.append(f"문법 검사 실패: error {error_count}건")
    if not ordering_passed:
        reasons.append("순서 검사 위반: " + "; ".join(ordering_issues))

    if not structure_passed or not syntax_passed:
        verdict = "REJECT"
    elif not ordering_passed:
        verdict = "REVIEW"
    else:
        verdict = "PASS"

    return {"verdict": verdict, "checks": checks, "reasons": reasons}


def _check_structure(chain: dict) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if not chain.get("technique_id"):
        issues.append("technique_id가 비어있다.")
    if not chain.get("goal"):
        issues.append("goal이 비어있다.")

    steps = chain.get("steps") or []
    if len(steps) == 0:
        issues.append("steps가 비어있다. 최소 1개 이상의 step이 필요하다.")

    orders: list[int] = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            issues.append(f"{i}번째 step이 객체(dict)가 아니다.")
            continue

        order = step.get("order")
        command = step.get("command")
        purpose = step.get("purpose")

        if isinstance(order, int) and not isinstance(order, bool):
            orders.append(order)
        else:
            issues.append(f"{i}번째 step(order={order!r})의 order가 정수가 아니다.")

        if not isinstance(command, str) or not command.strip():
            issues.append(f"{i}번째 step(order={order!r})의 command가 비어있다.")

        if not isinstance(purpose, str) or not purpose.strip():
            issues.append(f"{i}번째 step(order={order!r})의 purpose가 비어있다.")

    if steps and len(orders) == len(steps) and sorted(orders) != list(range(1, len(steps) + 1)):
        issues.append(f"order가 1부터 연속적이며 중복 없이 매겨져야 한다: {sorted(orders)}")

    return (len(issues) == 0, issues)


def _check_syntax(chain: dict) -> tuple[bool, list[dict]]:
    issues: list[dict] = []
    shellcheck_path = shutil.which("shellcheck")
    if shellcheck_path is None:
        issues.append(
            {"level": "warning", "message": "shellcheck가 설치되어 있지 않아 문법 검사를 건너뛴다."}
        )
        return True, issues

    passed = True
    for step in chain.get("steps") or []:
        if not isinstance(step, dict):
            continue
        command = step.get("command")
        if not isinstance(command, str) or not command.strip():
            continue  # 구조 검사에서 이미 다룬다

        order = step.get("order")
        try:
            result = subprocess.run(
                [shellcheck_path, "--shell=bash", "--format=json", "-"],
                input=command,
                capture_output=True,
                text=True,
                timeout=SHELLCHECK_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            issues.append(
                {"step_order": order, "level": "warning", "message": "shellcheck 실행이 시간 초과되어 건너뛴다."}
            )
            continue

        try:
            shellcheck_issues = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            issues.append(
                {"step_order": order, "level": "warning", "message": "shellcheck 출력 파싱에 실패했다."}
            )
            continue

        for sc_issue in shellcheck_issues:
            level = sc_issue.get("level")
            code = f"SC{sc_issue.get('code')}"
            issues.append(
                {
                    "step_order": order,
                    "level": level,
                    "code": code,
                    "message": sc_issue.get("message"),
                }
            )
            if level == "error" and code not in SHELLCHECK_IGNORE_CODES:
                passed = False

    return passed, issues


def _check_ordering(chain: dict, rules: dict) -> tuple[bool, list[str]]:
    technique_rules = rules.get(chain.get("technique_id"))
    if not technique_rules:
        return True, []

    steps = [
        step
        for step in chain.get("steps") or []
        if isinstance(step, dict)
        and isinstance(step.get("order"), int)
        and isinstance(step.get("command"), str)
    ]
    steps.sort(key=lambda step: step["order"])

    issues: list[str] = []
    for rule in technique_rules.get("requires_before", []):
        command_contains = rule.get("command_contains")
        must_follow = rule.get("must_follow")
        if not command_contains or not must_follow:
            continue

        for target in steps:
            if command_contains not in target["command"]:
                continue
            preceding = (s for s in steps if s["order"] < target["order"])
            if not any(must_follow in s["command"] for s in preceding):
                issues.append(
                    f"'{command_contains}'를 포함한 step(order={target['order']})은 "
                    f"'{must_follow}'를 포함한 step보다 먼저 나올 수 없다."
                )

    return (len(issues) == 0, issues)


def _load_rules() -> dict:
    if not RULES_PATH.exists():
        return {}
    with RULES_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


SAMPLE_CHAINS = {
    "PASS 예시": {
        "technique_id": "T1611",
        "goal": "마운트된 호스트 루트로 chroot하여 컨테이너를 탈출한다.",
        "steps": [
            {"order": 1, "command": "mount --bind / /mnt/host", "purpose": "호스트 루트 파일시스템을 마운트한다."},
            {"order": 2, "command": "chroot /mnt/host", "purpose": "마운트된 호스트로 루트를 전환해 탈출한다."},
        ],
    },
    "REJECT 예시 (구조 위반: goal 누락 + order 중복)": {
        "technique_id": "T1611",
        "goal": "",
        "steps": [
            {"order": 1, "command": "mount --bind / /mnt/host", "purpose": "호스트 마운트"},
            {"order": 1, "command": "chroot /mnt/host", "purpose": "루트 전환"},
        ],
    },
    "REVIEW 예시 (순서 위반: mount 없이 chroot)": {
        "technique_id": "T1611",
        "goal": "호스트로 chroot하여 탈출한다.",
        "steps": [
            {"order": 1, "command": "chroot /mnt/host", "purpose": "마운트 없이 곧바로 루트 전환을 시도한다."},
        ],
    },
    "PASS 예시 (docker run, --shell=bash 오탐 회귀 검증)": {
        "technique_id": "T1611",
        "goal": "취약한 옵션으로 컨테이너를 실행해 호스트 파일시스템에 접근한다.",
        "steps": [
            {
                "order": 1,
                "command": "docker run -d --name test -v $(pwd):/mnt/host_fs -p 80:80 -it ubuntu",
                "purpose": "호스트 디렉터리를 마운트한 컨테이너를 실행한다.",
            },
        ],
    },
    "REJECT 예시 (진짜 문법 오류: 따옴표 안 닫힘)": {
        "technique_id": "T1611",
        "goal": "따옴표가 닫히지 않은 명령으로 문법 검사 실패를 검증한다.",
        "steps": [
            {"order": 1, "command": 'echo "unclosed', "purpose": "문법 오류 케이스 검증용."},
        ],
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GraphRAG 생성 체인을 1차 필터로 검사한다"
    )
    parser.add_argument(
        "technique_id",
        nargs="?",
        default=None,
        help="지정 시 gemma로 실제 체인을 생성해 검사한다. 미지정 시 샘플 3개(PASS/REJECT/REVIEW)를 검사한다.",
    )
    args = parser.parse_args()

    if args.technique_id:
        from purplebpf.offensive.generation.generator import generate_chain

        chain = generate_chain(args.technique_id)
        print(json.dumps(filter_chain(chain), indent=2, ensure_ascii=False))
        return

    for name, chain in SAMPLE_CHAINS.items():
        print(f"=== {name} ===")
        print(json.dumps(filter_chain(chain), indent=2, ensure_ascii=False))
        print()


if __name__ == "__main__":
    main()
