#!/bin/bash
# 규칙을 어느 지점에 걸었느냐로 탐지가 갈린다는 것을 보여준다.
#
# 같은 공격(자격증명 파일 읽기)을 네 가지 경로로 실행하고,
# 두 규칙이 각각 잡는지 비교한다.
#   baseline  = 시스템콜 진입점(sys_openat)에 건 규칙
#   treatment = 커널 내부 함수(security_file_permission)에 건 규칙
set -e
cd /tmp

sudo mkdir -p /root/.ssh
echo "SYNTHETIC-CANARY-NOT-A-REAL-KEY" | sudo tee /root/.ssh/id_rsa >/dev/null
[ -x /tmp/iouring_read ] || gcc -O2 -o /tmp/iouring_read /tmp/iouring_read.c -luring

# mmap 으로 읽는 프로그램. 읽는 순간 시스템콜을 부르지 않는다.
cat > /tmp/mmap_read.py <<'PY'
import mmap, sys
f = open(sys.argv[1], "rb")
m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
len(m[:])
m.close(); f.close()
PY

# 이벤트를 실행한 프로그램으로 골라 센다.
#
# 시간창만으로 세면 앞 실행의 이벤트가 다음 창에 새어 들어온다.
# 실제로 io_uring 자리에 syscall 실행의 이벤트가 섞여 잡힌 것으로
# 나온 적이 있다. 어느 프로그램이 낸 이벤트인지로 거르면 그 일이 없다.
cat > /tmp/count.py <<'PY'
import json, sys

events, binary = sys.argv[1], sys.argv[2]
base = treat = 0
for line in open(events):
    try:
        k = json.loads(line).get("process_kprobe")
    except ValueError:
        continue
    if not k or binary not in (k.get("process", {}).get("binary") or ""):
        continue
    name = k.get("policy_name")
    if name == "t1552-001-cred-file-read-baseline":
        base += 1
    elif name == "t1552-001-cred-file-read":
        treat += 1
print(base, treat)
PY

run() {   # run <라벨> <이벤트를 낼 프로그램> <명령...>
  local label="$1" binary="$2"; shift 2
  docker exec tetragon timeout 8 tetra getevents -o json > /tmp/demo.json 2>/dev/null &
  sleep 3
  "$@" >/dev/null 2>&1 || true
  wait
  read -r b t < <(python3 /tmp/count.py /tmp/demo.json "$binary")
  printf '  %-16s %-12s %s\n' "$label" \
    "$([ "$b" -gt 0 ] && echo "잡힘($b)" || echo '놓침')" \
    "$([ "$t" -gt 0 ] && echo "잡힘($t)" || echo '놓침')"
}

echo
echo "  공격      /root/.ssh/id_rsa 읽기 (합성 카나리 파일)"
echo "  baseline  sys_openat               시스템콜 진입점"
echo "  treatment security_file_permission 커널 내부 함수"
echo
printf '  %-16s %-12s %s\n' "읽는 방식" "baseline" "treatment"
printf '  %s\n' "----------------------------------------------"
run "syscall"        /bin/cat            sudo cat /root/.ssh/id_rsa
run "io_uring"       /tmp/iouring_read   sudo /tmp/iouring_read /root/.ssh/id_rsa
run "io_uring async" /tmp/iouring_read   sudo /tmp/iouring_read /root/.ssh/id_rsa --async
run "mmap"           python3             sudo python3 /tmp/mmap_read.py /root/.ssh/id_rsa
echo
