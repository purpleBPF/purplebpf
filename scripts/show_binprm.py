"""security_bprm_check 이벤트에서 세 가지를 나란히 보여준다.

  실행될 것  linux_binprm 인자. 지금 막 실행되려는 프로그램
  호출자     process.binary. execve 를 부른 프로세스
  부모       parent.binary

matchBinaries 와 matchParentBinaries 가 각각 무엇을 보는지 가리는 용도다.
"""

import json
import sys

policy = sys.argv[2] if len(sys.argv) > 2 else None

for line in open(sys.argv[1]):
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    k = ev.get("process_kprobe")
    if not k:
        continue
    if policy and k.get("policy_name") != policy:
        continue
    new = ""
    for a in k.get("args") or []:
        if "linux_binprm_arg" in a:
            new = a["linux_binprm_arg"].get("path", "")
    caller = (k.get("process") or {}).get("binary", "?")
    parent = (k.get("parent") or {}).get("binary", "?")
    print(f"  실행될것={new:16} 호출자={caller:20} 부모={parent}")
