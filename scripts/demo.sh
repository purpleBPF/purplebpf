#!/bin/bash
# io_uring 대조실험 데모. 같은 공격(자격증명 파일 읽기)을 두 경로로 쏘고
# baseline(시스템콜 진입점) 과 treatment(커널 내부 함수) 정책의 탐지 결과를 비교한다.
set -e
cd /tmp

sudo mkdir -p /root/.ssh
echo "SYNTHETIC-CANARY-NOT-A-REAL-KEY" | sudo tee /root/.ssh/id_rsa >/dev/null
[ -x /tmp/iouring_read ] || gcc -O2 -o /tmp/iouring_read /tmp/iouring_read.c -luring

run() {   # run <라벨> <명령...>
  local label="$1"; shift
  docker exec tetragon timeout 8 tetra getevents -o json > /tmp/demo.json 2>/dev/null &
  sleep 3
  "$@" >/dev/null 2>&1
  wait
  local b t
  b=$(grep -c pbpf-01-cred-file-read-baseline  /tmp/demo.json || true)
  t=$(grep -c pbpf-01-cred-file-read-treatment /tmp/demo.json || true)
  printf '%-16s  baseline %-8s  treatment %s\n' "$label" \
    "$([ "$b" -gt 0 ] && echo "잡힘($b)" || echo '놓침(0)')" \
    "$([ "$t" -gt 0 ] && echo "잡힘($t)" || echo '놓침(0)')"
}

echo "공격: /root/.ssh/id_rsa 읽기"
echo "baseline  = sys_openat            (시스템콜 진입점)"
echo "treatment = security_file_permission (커널 내부 함수)"
echo
run "일반 read"      sudo cat /root/.ssh/id_rsa
run "io_uring read"  sudo /tmp/iouring_read /root/.ssh/id_rsa
run "io_uring async" sudo /tmp/iouring_read /root/.ssh/id_rsa --async
