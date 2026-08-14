#!/bin/bash
# 정상 워크로드를 돌려 오탐을 잰다.
#
# 공격 싸이클(run_cycle.sh)과 구조가 같다. Mapper 를 먼저 띄워 이벤트를
# 수집하면서 워크로드를 실행하고, 끝나면 어느 규칙이 떴는지 집계한다.
#
# 판정
#   CLEAN       아무 규칙도 안 떴다
#   FP          조용해야 한다고 적어둔 규칙이 떴다. 확정 오탐
#   UNEXPECTED  예상 못 한 규칙이 떴다. 사람이 봐야 한다
#
# 사용법: demo/run_benign.sh [round_id]
set -euo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
export DOCKER_HOST=unix:///Users/jaewoo/.lima/purplebpf/sock/docker.sock
export PYTHONPATH=src
PY=.venv/bin/python

COUNT=$(ls demo/benign/*.json 2>/dev/null | wc -l | tr -d ' ')
[ "$COUNT" = "0" ] && { echo "demo/benign 에 시나리오가 없다."; exit 1; }

ROUND=${1:-$($PY - <<'PY'
import os, sqlalchemy as sa
e = sa.create_engine(os.environ["DATABASE_URL"])
with e.connect() as c:
    print(c.execute(sa.text("select coalesce(max(round_id),0)+1 from benign_log")).scalar_one())
PY
)}

# 시나리오 하나에 컨테이너 하나를 띄우고 지운다. 그 왕복이 실측 2초쯤이다.
WINDOW=${PBPF_WINDOW:-$(( COUNT * 3 + 25 ))}

echo "=== Mapper 기동 (${WINDOW}초 수집) ==="
limactl shell purplebpf -- docker exec tetragon timeout "$WINDOW" tetra getevents -o json \
    < /dev/null 2>/dev/null \
  | $PY -m purplebpf.defensive.mapper.mapper > /tmp/pbpf-benign-mapper.log 2>&1 &
MAPPER=$!
sleep 6

echo "=== 정상 워크로드 실행 (round ${ROUND}, ${COUNT}개) ==="
$PY -m purplebpf.offensive.executor.benign_runner --dir demo/benign --round-id "$ROUND"

echo "=== Mapper 종료 대기 ==="
wait $MAPPER 2>/dev/null || true
echo "detections 기록 $(grep -c '^기록' /tmp/pbpf-benign-mapper.log || echo 0) 건"
echo

docker --context lima-purplebpf compose exec -T postgres \
  psql -U purplebpf -d purplebpf -c \
  "SELECT result, COUNT(*) AS 시나리오수
   FROM benign_summary WHERE round_id = ${ROUND} GROUP BY result ORDER BY result;"

echo "규칙이 뜬 시나리오"
docker --context lima-purplebpf compose exec -T postgres \
  psql -U purplebpf -d purplebpf -c \
  "SELECT label, kind, rule_name, hits, was_expected_silent AS 조용해야_했나
   FROM false_positives WHERE round_id = ${ROUND}
   ORDER BY was_expected_silent DESC, hits DESC LIMIT 20;"
