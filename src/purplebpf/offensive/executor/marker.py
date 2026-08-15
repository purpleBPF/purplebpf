"""공격 스텝에 난수 마커를 붙이고 실행로그를 남긴다.

마커는 유일한 경로의 파일을 만들고 읽는 것이다. 그 경로가 Tetragon 이벤트에
그대로 찍히므로, 이벤트 스트림 안에 "여기부터 여기까지가 이 스텝" 이라는
울타리가 생긴다. 시계를 맞출 필요가 없는 게 시간 조인 대비 장점.

채점기는 begin/end 마커 사이의 이벤트를 그 스텝 것으로 본다.
"""

import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

MARKER_ROOT = Path("/tmp/pbpf")


def _marker(nonce: str, step: int, edge: str) -> None:
    p = MARKER_ROOT / nonce / f"{step:02d}.{edge}"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.touch()
    p.read_bytes()  # openat + read 이벤트를 확실히 만들려고 실제로 읽는다


def container_id() -> str:
    """cgroup v2 + cgroup 네임스페이스면 '0::/' 만 나와서 못 구한다.
    그 경우 오케스트레이터가 PBPF_CONTAINER_ID 로 주입해야 한다."""
    if cid := os.environ.get("PBPF_CONTAINER_ID"):
        return cid
    try:
        line = Path("/proc/self/cgroup").read_text().strip().rsplit("/", 1)[-1]
    except OSError:
        return ""
    return line if len(line) >= 12 else ""


@contextmanager
def step(
    run_id: str,
    chain_id: str,
    index: int,
    technique_id: str,
    channel: str = "syscall",
    verify=None,
    log_path: str = "exec_log.jsonl",
):
    """공격 스텝 하나를 감싼다. yield 되는 값이 이 스텝의 난수.

    verify: 스텝이 실제로 성공했는지 확인하는 함수. 없으면 ok=None.
            이게 없으면 EPERM 으로 죽은 공격도 "쐈다"로 기록되고,
            탐지가 안 뜨는 게 당연해져서 가짜 FN 이 된다.
    """
    nonce = uuid.uuid4().hex
    _marker(nonce, index, "begin")
    t0 = time.time_ns()
    err = None
    try:
        yield nonce
    except Exception as e:
        err = repr(e)
        raise
    finally:
        t1 = time.time_ns()
        _marker(nonce, index, "end")
        ok = None if verify is None else (bool(verify()) if err is None else False)
        rec = {
            "run_id": run_id,
            "chain_id": chain_id,
            "step_index": index,
            "technique_id": technique_id,
            "nonce": nonce,
            "channel": channel,
            "container_id": container_id(),
            "pid": os.getpid(),  # 컨테이너 네임스페이스 PID. 조인 보조용일 뿐 주 키 아님
            "t_begin_ns": t0,
            "t_end_ns": t1,
            "ok": ok,
            "error": err,
        }
        with open(log_path, "a") as f:
            f.write(json.dumps(rec) + "\n")


if __name__ == "__main__":
    import tempfile

    log = tempfile.mktemp(suffix=".jsonl")
    target = Path(tempfile.mktemp())

    with step("run1", "chain1", 1, "T1548.001", verify=target.exists, log_path=log) as n:
        target.touch()
        assert (MARKER_ROOT / n / "01.begin").exists()

    rec = json.loads(Path(log).read_text().strip())
    assert rec["ok"] is True, rec
    assert rec["nonce"] and rec["technique_id"] == "T1548.001"
    assert (MARKER_ROOT / rec["nonce"] / "01.end").exists()

    # 실패한 스텝은 ok=False 로 남아야 한다 (가짜 FN 방지)
    try:
        with step("run1", "chain1", 2, "T1548.001", verify=lambda: True, log_path=log):
            raise PermissionError("EPERM")
    except PermissionError:
        pass
    rec2 = json.loads(Path(log).read_text().strip().splitlines()[-1])
    assert rec2["ok"] is False and "EPERM" in rec2["error"], rec2

    print("ok")
