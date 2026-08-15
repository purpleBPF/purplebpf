"""시나리오 명령이 실제로 도는지 확인한다. DB 도 Tetragon 도 안 쓴다.

안전성 검사(test_benign_safety.py)는 쓰면 안 되는 것을 안 썼는지만 본다.
명령이 문법적으로 깨졌는지, 없는 프로그램을 불렀는지는 돌려봐야 안다.
파이썬 코드를 셸 한 줄에 밀어 넣은 시나리오가 많아 따옴표가 쉽게 깨진다.

실행 조건은 benign_runner 와 같게 맞춘다. 여기서 통과한 것이 실제 측정에서
실패하면 안 되기 때문이다.

    python tests/smoke_benign.py [--dir demo/benign] [--only 이름조각]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor

import docker

BASE_IMAGE = "ubuntu:22.04"
STEP_TIMEOUT_SECONDS = 30


def check(client: docker.DockerClient, path: pathlib.Path) -> tuple[str, list[str]]:
    scenario = json.loads(path.read_text(encoding="utf-8"))
    label = scenario["label"]
    steps = sorted(scenario.get("steps") or [], key=lambda s: s["order"])

    container = client.containers.run(
        BASE_IMAGE, command=["sleep", "infinity"], detach=True,
        privileged=False, network_mode="bridge", cap_add=[],
        security_opt=["no-new-privileges"],
    )
    failures: list[str] = []
    try:
        for step in steps:
            wrapped = f"timeout {STEP_TIMEOUT_SECONDS}s bash -c {shlex.quote(step['command'])}"
            r = container.exec_run(["bash", "-c", wrapped], demux=False)
            if r.exit_code != 0:
                out = (r.output or b"").decode("utf-8", errors="replace").strip()
                tail = out.splitlines()[-3:] if out else ["(출력 없음)"]
                failures.append(
                    f"step{step['order']} rc={r.exit_code}\n"
                    f"      명령: {step['command'][:160]}\n"
                    + "".join(f"      출력: {line[:160]}\n" for line in tail)
                )
    finally:
        try:
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
    return label, failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="demo/benign")
    ap.add_argument("--only", help="이름에 이 조각이 든 시나리오만 돌린다")
    ap.add_argument("--jobs", type=int, default=6)
    args = ap.parse_args()

    files = sorted(pathlib.Path(args.dir).glob("*.json"))
    if args.only:
        files = [f for f in files if args.only in f.stem]
    if not files:
        print(f"{args.dir} 에 시나리오가 없다.")
        return 1

    client = docker.from_env()
    print(f"시나리오 {len(files)}개를 컨테이너에서 실행한다 (동시 {args.jobs})\n")

    bad = 0
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for label, failures in pool.map(lambda p: check(client, p), files):
            if failures:
                bad += 1
                print(f"  실패 {label}")
                for f in failures:
                    print(f"    {f}")

    ok = len(files) - bad
    print(f"\n통과 {ok} / 실패 {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
