"""정상 워크로드 시나리오가 안전한지 검사한다.

이 시나리오들은 격리 컨테이너에서 실행되지만, 그래도 건드리면 안 되는
경로와 동작이 있다. 컨테이너 밖으로 새는 것과, 되돌릴 수 없는 것이다.
시나리오는 자동 생성되므로 실행 전에 기계적으로 걸러야 한다.

python3 tests/test_benign_safety.py
"""

import json
import pathlib
import re
import sys

BENIGN_DIR = pathlib.Path(__file__).resolve().parents[1] / "demo" / "benign"

RULES = {
    "t1548-001-setuid-bit-set", "t1548-003-sudo-abuse", "t1552-001-cred-file-read",
    "t1552-005-cloud-metadata", "t1105-tmp-exec", "t1611-namespace-change",
    "t1611-host-mount", "t1610-runtime-socket-connect", "t1613-container-discovery",
    "t1620-fileless-exec", "t1562-001-defense-tamper", "t1055-008-ptrace-inject",
    "t1055-009-proc-mem-inject", "exec-admin-tools", "exec-file-capability",
}

# 건드리면 안 되는 것들. 컨테이너 안이라도 금지한다.
FORBIDDEN = [
    (r"/var/run/docker\.sock|/run/docker\.sock", "런타임 소켓 경로를 건드린다"),
    (r"/run/containerd|/var/run/containerd|crio\.sock", "런타임 소켓 경로를 건드린다"),
    (r"\brm\s+-rf\s+/\s*(;|&|$)", "루트를 지운다"),
    (r"\bmkfs|\bfdisk|\bdd\s+.*of=/dev/(sd|nvme|vd)", "디스크를 건드린다"),
    (r"\bcurl\b|\bwget\b.*https?://(?!127\.0\.0\.1|localhost)", "외부로 나간다"),
    # 실제로 접속하는 명령과 함께 쓰일 때만 잡는다. 문자열로 언급하고
    # grep 으로 찾는 것은 접속이 아니다.
    (r"(curl|wget|nc|/dev/tcp)\S*\s*[^;|&]*169\.254\.169\.254", "메타데이터 주소로 접속한다"),
    (r"\bchmod\s+[0-7]*[4267][0-7]{3}\b", "setuid 또는 setgid 비트를 세운다"),
    (r"\bchmod\s+\S*[ug]\+s", "setuid 또는 setgid 비트를 세운다"),
    (r">\s*/etc/(passwd|shadow|sudoers)\s*$", "시스템 계정 파일을 덮어쓴다"),
]


def main() -> int:
    files = sorted(BENIGN_DIR.glob("*.json"))
    if not files:
        print("시나리오가 없다.", file=sys.stderr)
        return 1

    problems: list[str] = []
    labels: set[str] = set()

    for path in files:
        s = json.loads(path.read_text(encoding="utf-8"))
        name = path.name

        for field in ("label", "kind", "goal", "expect_silent", "steps"):
            if field not in s:
                problems.append(f"{name}: {field} 없음")

        label = s.get("label", "")
        if label in labels:
            problems.append(f"{name}: label 중복 ({label})")
        labels.add(label)
        if path.stem != label:
            problems.append(f"{name}: 파일 이름과 label 이 다르다 ({label})")

        if s.get("kind") not in ("normal", "trap"):
            problems.append(f'{name}: kind 가 normal/trap 이 아니다 ({s.get("kind")})')

        for rule in s.get("expect_silent", []):
            if rule not in RULES:
                problems.append(f"{name}: 없는 규칙 이름 ({rule})")
        if s.get("kind") == "trap" and not s.get("expect_silent"):
            problems.append(f"{name}: trap 인데 expect_silent 가 비었다")

        orders = [st.get("order") for st in s.get("steps", [])]
        if orders != sorted(orders):
            problems.append(f"{name}: step order 가 순서대로가 아니다")
        if not s.get("steps"):
            problems.append(f"{name}: steps 가 비었다")

        for st in s.get("steps", []):
            cmd = st.get("command", "")
            for pattern, why in FORBIDDEN:
                if re.search(pattern, cmd):
                    problems.append(f'{name} step{st.get("order")}: {why}\n      {cmd[:100]}')

    print(f"시나리오 {len(files)}개 검사")
    if problems:
        print(f"\n문제 {len(problems)}건")
        for p in problems:
            print(f"  {p}")
        return 1
    print("문제 없음")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
