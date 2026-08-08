#!/bin/bash
# 규칙을 어디에 거느냐로 탐지가 갈린다는 것을 보여준다.
#
# VM 의 /tmp 는 재부팅하면 비워지므로, 필요한 파일을 매번 레포에서
# 복사해 넣고 실행한다. 그래서 VM 을 껐다 켠 뒤에도 그냥 돌아간다.
set -euo pipefail
cd "$(dirname "$0")/.."

VM=purplebpf

limactl copy scripts/demo.sh scripts/iouring_read.c "$VM:/tmp/" >/dev/null 2>&1
limactl shell "$VM" bash -c '
  chmod +x /tmp/demo.sh
  # liburing 이 없으면 설치한다. 이미 있으면 넘어간다.
  if ! dpkg -s liburing-dev >/dev/null 2>&1; then
    echo "  liburing-dev 설치 중..."
    sudo apt-get install -y -qq gcc liburing-dev >/dev/null 2>&1
  fi
  gcc -O2 -o /tmp/iouring_read /tmp/iouring_read.c -luring
  /tmp/demo.sh
'
