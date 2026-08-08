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

BASE='"policy_name":"t1552-001-cred-file-read-baseline"'
TREAT='"policy_name":"t1552-001-cred-file-read"'

run() {   # run <라벨> <명령...>
  local label="$1"; shift
  docker exec tetragon timeout 8 tetra getevents -o json > /tmp/demo.json 2>/dev/null &
  sleep 3
  "$@" >/dev/null 2>&1 || true
  wait
  # policy_name 을 통째로 매칭한다. 부분 문자열로 세면 treatment 쪽이
  # baseline 이벤트까지 같이 집계한다.
  local b t
  b=$(grep -c "$BASE"  /tmp/demo.json || true)
  t=$(grep -c "$TREAT" /tmp/demo.json || true)
  printf '  %-16s %-12s %s\n' "$label" \
    "$([ "$b" -gt 0 ] && echo "잡힘($b)" || echo '놓침')" \
    "$([ "$t" -gt 0 ] && echo "잡힘($t)" || echo '놓침')"
}

echo
echo "  공격      /root/.ssh/id_rsa 읽기 (합성 카나리 파일)"
echo "  baseline  sys_openat              시스템콜 진입점"
echo "  treatment security_file_permission 커널 내부 함수"
echo
printf '  %-16s %-12s %s\n' "읽는 방식" "baseline" "treatment"
printf '  %s\n' "----------------------------------------------"
run "syscall"        sudo cat /root/.ssh/id_rsa
run "io_uring"       sudo /tmp/iouring_read /root/.ssh/id_rsa
run "io_uring async" sudo /tmp/iouring_read /root/.ssh/id_rsa --async
run "mmap"           sudo python3 /tmp/mmap_read.py /root/.ssh/id_rsa
echo
echo "  io_uring 은 시스템콜 진입점을 지나지 않아 baseline 이 놓친다."
echo "  mmap 은 읽기가 권한 검사를 지나지 않아 treatment 가 놓친다."
echo "  둘은 서로 다른 사각지대다. 어느 한쪽이 우월한 것이 아니다."
echo
