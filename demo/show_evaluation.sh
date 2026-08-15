#!/bin/bash
# 지금까지 쌓인 데이터로 규칙 품질을 한 화면에 보여준다.
#
# 공격을 쏘면 재현율이 나오고 정상 워크로드를 돌리면 정밀도가 나온다.
# 둘을 같이 봐야 규칙을 좁힐지 넓힐지 정할 수 있다.
set -euo pipefail
. "$(dirname "$0")/_env.sh"

echo
echo "================ 규칙별 점수판 ================"
echo "  tp 는 공격을 잡은 횟수, fp 는 정상 워크로드에서 뜬 횟수다."
echo "  fp_확정 은 그 시나리오가 조용해야 한다고 미리 적어둔 경우다."
$PSQL -c "SELECT rule_name, tp, fp, fp_확정, 정밀도
          FROM rule_scorecard WHERE tp > 0 OR fp > 0
          ORDER BY 정밀도 NULLS LAST, fp DESC;"

echo "================ 정상 워크로드 판정 ================"
echo "  CLEAN 은 아무 규칙도 안 뜬 것, FP 는 조용해야 할 규칙이 뜬 것,"
echo "  UNEXPECTED 는 예상 못 한 규칙이 뜬 것이다."
$PSQL -c "SELECT result, COUNT(*) AS 시나리오수
          FROM benign_summary
          WHERE round_id = (SELECT MAX(round_id) FROM benign_log)
          GROUP BY result ORDER BY result;"

echo "================ 규칙이 뜬 정상 워크로드 ================"
$PSQL -c "SELECT label, kind, rule_name, hits, was_expected_silent AS 조용해야_했나
          FROM false_positives
          WHERE round_id = (SELECT MAX(round_id) FROM benign_log)
          ORDER BY was_expected_silent DESC, hits DESC;"

echo "================ 최근 라운드 종합 ================"
$PSQL -c "SELECT round_id, tp, fn, invalid, fp, tn, 재현율, 정밀도, f1
          FROM overall_metrics ORDER BY round_id DESC LIMIT 5;"
