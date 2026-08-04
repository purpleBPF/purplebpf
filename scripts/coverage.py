"""정책별로 이벤트가 몇 건 떴는지 집계한다. 0건이면 그 룰은 발화하지 않은 것.

로드된 정책 목록을 인자로 받아, 이벤트가 안 뜬 정책도 0으로 표시한다.
안 그러면 "안 뜬 룰"이 표에서 아예 사라져서 검증이 안 된다.
"""

import json
import sys
from collections import Counter

events, loaded = sys.argv[1], sys.argv[2]

count = Counter()
for line in open(events):
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    k = ev.get("process_kprobe") or ev.get("process_tracepoint")
    if not k:
        continue
    name = k.get("policy_name", "")
    if name.startswith("pbpf"):
        count[name] += 1

names = sorted(n for n in open(loaded).read().split() if n.startswith("pbpf"))
fired = 0
for n in names:
    c = count[n]
    fired += c > 0
    print(f'{"발화" if c else "  0 "}  {n:42} {c:5}')
print(f"--- 정책 {len(names)}개 중 {fired}개 발화")
