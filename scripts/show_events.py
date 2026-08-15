"""tetra getevents -o json 출력에서 pbpf 정책 이벤트만 뽑아 한 줄씩 보여준다."""

import json
import sys


def path_of(args):
    for a in args or []:
        if "file_arg" in a:
            return a["file_arg"].get("path", "")
        if "string_arg" in a:
            return a["string_arg"]
        if "path_arg" in a:
            return a["path_arg"].get("path", "")
        if "linux_binprm_arg" in a:
            return a["linux_binprm_arg"].get("path", "")
        if "sock_arg" in a:
            s = a["sock_arg"]
            return f'{s.get("daddr")}:{s.get("dport")}'
        if "sockaddr_arg" in a:
            return a["sockaddr_arg"].get("addr", "")
    return ""


hits = 0
for line in open(sys.argv[1]):
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    k = ev.get("process_kprobe") or ev.get("process_tracepoint")
    if not k:
        continue
    pol = k.get("policy_name", "")
    if not pol.startswith("pbpf"):
        continue
    hits += 1
    fn = k.get("function_name") or k.get("subsys", "")
    proc = k.get("process", {})
    print(f'{pol:42} {fn:28} {proc.get("binary","?"):20} {path_of(k.get("args"))}')

print(f"--- pbpf 이벤트 {hits}건")
