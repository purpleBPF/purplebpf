#!/bin/bash
# 한 싸이클: 공격 실행(y_true) → Tetragon 탐지(y_pred) → 조인 → TP/FN/FP
#
# 전제
#   - lima VM `purplebpf` 에 Tetragon 이 떠 있고 룰팩이 로드돼 있을 것
#   - docker compose 로 postgres 가 떠 있고 alembic upgrade head 가 끝났을 것
#
# 사용법: demo/run_cycle.sh [round_id]
#   round_id 를 안 주면 마지막 라운드 + 1 로 자동 증가한다.
#   라운드는 루프의 세대다. 같은 라운드에 두 번 쏘면 채점이 두 번 겹쳐
#   집계되므로(재현율은 같고 건수만 배로 늘어난다) 매 실행이 새 라운드여야 한다.
set -euo pipefail
. "$(dirname "$0")/_env.sh"

ROUND=${1:-$($PY - <<'PY'
import os, sqlalchemy as sa
e = sa.create_engine(os.environ["DATABASE_URL"])
with e.connect() as c:
    print(c.execute(sa.text("select coalesce(max(round_id),0)+1 from execution_log")).scalar_one())
PY
)}

CHAINS=(t1548_001 t1105 t1552_001 t1552_005 t1611 t1613 t1055_008 t1055_009 t1548_003 t1562_001 t1620 t1059_004)

# 수집 창. 체인 하나는 실측 1초 안에 끝나고, 앞뒤로 Mapper 기동 대기와
# 이벤트 도착 지연을 흡수할 여유를 둔다. 창이 너무 짧으면 마지막 공격의
# 탐지가 창 밖에서 도착해 미탐으로 잘못 계상된다.
WINDOW=${PBPF_WINDOW:-$(( ${#CHAINS[@]} * 3 + 25 ))}

echo "=== Mapper 기동 (${WINDOW}초 수집) ==="
# stdin 을 막지 않으면 백그라운드의 limactl 이 루프의 stdin 을 가져간다.
# 리다이렉션은 반드시 limactl 쪽에 건다. 파이프라인 끝에 걸면 Mapper 가
# 이벤트 대신 /dev/null 을 읽어 아무것도 기록하지 않는다.
limactl shell "$PBPF_LIMA_VM" -- docker exec tetragon timeout "$WINDOW" tetra getevents -o json \
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
