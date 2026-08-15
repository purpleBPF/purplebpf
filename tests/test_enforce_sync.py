"""차단판이 관측판과 같은 것을 막는지 검사한다.

두 판은 훅과 조건이 같고 matchActions 만 달라야 한다. 관측판만 고치고
차단판을 안 고치면 조용히 어긋난다. 실제로 t1613 에서 그렇게 됐다.
관측판을 좁혀 오탐을 없앴는데 차단판은 넓은 조건 그대로여서, 올리면
df 와 /sys/fs/cgroup 읽기까지 막는 상태였다.

어긋나면 대가가 크다. 관측판으로 잰 정밀도가 차단판의 정밀도가 아니게 된다.
오탐 한 건과 "정상 동작이 막힘" 은 다른 무게다.

selector 마다 matchActions 가 붙었는지도 본다. 하나에만 붙이면 나머지는
관측만 하고 안 막는데, 파일 이름이 enforce 라 막히는 줄 알게 된다.

    python tests/test_enforce_sync.py
"""
from __future__ import annotations

import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
OBSERVE = ROOT / "rules" / "tracingpolicies" / "observe"
ENFORCE = ROOT / "rules" / "tracingpolicies" / "enforce"


def hooks(doc: dict) -> list[str]:
    """거는 훅 목록. 조건이 없는 훅은 selector 를 안 만들어서 조건 비교만으로는
    안 잡힌다. 훅 자체가 빠지거나 늘어난 것을 보려면 따로 봐야 한다."""
    return [kprobe["call"] for kprobe in doc["spec"]["kprobes"]]


def selectors(doc: dict) -> list[tuple]:
    """(훅, matchActions 를 뺀 조건) 목록. 순서까지 같아야 한다."""
    out = []
    for kprobe in doc["spec"]["kprobes"]:
        for sel in kprobe.get("selectors") or []:
            condition = {k: v for k, v in sel.items() if k != "matchActions"}
            out.append((kprobe["call"], condition, bool(sel.get("matchActions"))))
    return out


def main() -> int:
    problems: list[str] = []
    files = sorted(ENFORCE.glob("*.yaml"))
    if not files:
        print(f"{ENFORCE} 에 차단판이 없다.")
        return 1

    for path in files:
        enforce = yaml.safe_load(path.read_text(encoding="utf-8"))
        observe_path = OBSERVE / path.name
        if not observe_path.exists():
            problems.append(f"{path.name}: 짝이 되는 관측판이 없다")
            continue
        observe = yaml.safe_load(observe_path.read_text(encoding="utf-8"))

        if enforce["metadata"]["name"] != observe["metadata"]["name"]:
            problems.append(
                f"{path.name}: metadata.name 이 다르다 "
                f"({enforce['metadata']['name']} vs {observe['metadata']['name']}). "
                "같은 이름이어야 모드가 바뀌어도 같은 규칙으로 집계된다"
            )

        if hooks(enforce) != hooks(observe):
            problems.append(
                f"{path.name}: 거는 훅이 다르다. "
                f"차단판 {hooks(enforce)}, 관측판 {hooks(observe)}"
            )

        e, o = selectors(enforce), selectors(observe)
        if [x[:2] for x in e] != [x[:2] for x in o]:
            problems.append(
                f"{path.name}: 조건이 관측판과 다르다. "
                f"차단판 selector {len(e)}개, 관측판 {len(o)}개. "
                "관측판을 고쳤으면 차단판도 같이 고쳐야 한다"
            )

        missing = [i for i, x in enumerate(e) if not x[2]]
        if missing:
            problems.append(
                f"{path.name}: selector {missing} 에 matchActions 가 없다. "
                "그 조건은 관측만 하고 안 막는다"
            )

    print(f"차단판 {len(files)}개 검사")
    if problems:
        print(f"\n문제 {len(problems)}건")
        for p in problems:
            print(f"  {p}")
        return 1
    print("문제 없음")
    return 0


if __name__ == "__main__":
    sys.exit(main())
