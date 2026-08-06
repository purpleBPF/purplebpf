#!/bin/bash
# 한 싸이클: 공격 실행(y_true) → Tetragon 탐지(y_pred) → 조인 → TP/FN/FP
#
# 전제
#   - lima VM `purplebpf` 에 Tetragon 이 떠 있고 룰팩이 로드돼 있을 것
#   - docker compose 로 postgres 가 떠 있고 alembic upgrade head 가 끝났을 것
#
# 사용법: demo/run_cycle.sh [round_id]
set -euo pipefail
cd "$(dirname "$0")/.."

ROUND=${1:-1}
set -a; . ./.env; set +a
export DOCKER_HOST=unix:///Users/jaewoo/.lima/purplebpf/sock/docker.sock
export PYTHONPATH=src           # editable install 의 .pth 가 처리 안 되는 환경 대비
PY=.venv/bin/python

CHAINS=(t1548_001 t1105 t1552_001 t1552_005 t1611 t1613)
WINDOW=$(( ${#CHAINS[@]} * 25 + 30 ))

echo "=== Mapper 기동 (${WINDOW}초 수집) ==="
# stdin 을 막지 않으면 백그라운드의 limactl 이 루프의 stdin 을 가져간다.
# 리다이렉션은 반드시 limactl 쪽에 건다. 파이프라인 끝에 걸면 Mapper 가
# 이벤트 대신 /dev/null 을 읽어 아무것도 기록하지 않는다.
limactl shell purplebpf -- docker exec tetragon timeout "$WINDOW" tetra getevents -o json \
    < /dev/null 2>/dev/null \
  | $PY -m purplebpf.defensive.mapper.mapper > /tmp/pbpf-mapper.log 2>&1 &
MAPPER=$!
sleep 6

echo "=== 공격 실행 (round ${ROUND}) ==="
for c in "${CHAINS[@]}"; do
  printf '%-12s ' "$c"
  $PY -m purplebpf.offensive.executor.executor \
      --chain-file "demo/chains/$c.json" --round-id "$ROUND" 2>&1 \
    | grep -E '"(success|container_id|run_id)"' | tr -d ' ",' | tr '\n' ' ' || true
  echo
done

echo "=== Mapper 종료 대기 ==="
wait $MAPPER 2>/dev/null || true
echo "detections 기록 $(grep -c '^기록' /tmp/pbpf-mapper.log || echo 0) 건"

echo
$PY -m purplebpf.data.coverage --round "$ROUND"
