#!/bin/bash
# 폐쇄 루프가 실제로 도는 것을 두 라운드로 보여준다.
#
#   라운드 N     T1613 규칙을 뺀 상태로 공격 → 놓친다(FN)
#   규칙 투입     FN 목록을 보고 규칙을 만든다
#   라운드 N+1   같은 공격 → 잡힌다(TP), 재현율이 오른다
#
# 이것이 이 프로젝트의 주장 그 자체다. 놓친 것을 알아내고, 메우고,
# 메워졌는지 숫자로 확인한다.
set -euo pipefail
. "$(dirname "$0")/_env.sh"
POLICY=t1613-container-discovery
FILE=/etc/tetragon/tetragon.tp.d/t1613_container_discovery.yaml

hr() { printf '%s\n' "------------------------------------------------------------"; }

hr
echo " 1단계  T1613 탐지 규칙을 내린다"
hr
limactl shell "$PBPF_LIMA_VM" -- docker exec tetragon tetra tracingpolicy delete "$POLICY" 2>&1 | tail -1 || true
echo

./demo/run_cycle.sh
R1=$($PY - <<'PY'
import os, sqlalchemy as sa
e = sa.create_engine(os.environ["DATABASE_URL"])
with e.connect() as c:
    print(c.execute(sa.text("select max(round_id) from execution_log")).scalar_one())
PY
)

echo
hr
echo " 2단계  놓친 기법을 보고 규칙을 투입한다"
hr
limactl shell "$PBPF_LIMA_VM" -- docker exec tetragon tetra tracingpolicy add "$FILE" 2>&1 | tail -1
echo

./demo/run_cycle.sh
R2=$($PY - <<'PY'
import os, sqlalchemy as sa
e = sa.create_engine(os.environ["DATABASE_URL"])
with e.connect() as c:
    print(c.execute(sa.text("select max(round_id) from execution_log")).scalar_one())
PY
)

echo
hr
echo " 결과  라운드 ${R1} → ${R2}"
hr
$PSQL -c "SELECT round_id, tp, fn, invalid, recall_pct AS 재현율
   FROM recall_by_round WHERE round_id IN (${R1}, ${R2}) ORDER BY round_id;"

$PSQL -c "SELECT round_id, technique, shots, detects, result
   FROM coverage_by_round WHERE round_id IN (${R1}, ${R2}) AND technique = 'T1613'
   ORDER BY round_id;"
