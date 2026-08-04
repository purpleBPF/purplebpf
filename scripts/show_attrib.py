"""pbpf 정책 이벤트의 프로세스 귀속 필드를 보여준다.

io_uring 작업이 io_wq 커널 워커(iou-wrk-*)에서 수행될 때 이벤트가
링 소유 프로세스로 귀속되는지, 워커로 새는지 확인하는 용도.
binary 가 iou-wrk-* 면 조인 키가 깨진다는 뜻이다.
"""

import json
import sys

n = 0
for line in open(sys.argv[1]):
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    k = ev.get("process_kprobe")
    if not k or not k.get("policy_name", "").startswith("pbpf"):
        continue
    p = k["process"]
    n += 1
    print(f"policy   = {k['policy_name']}")
    print(f"  fn     = {k['function_name']}")
    print(f"  binary = {p.get('binary')}")
    print(f"  pid    = {p.get('pid')}   tid = {p.get('tid')}")
print(f"--- {n}건")
