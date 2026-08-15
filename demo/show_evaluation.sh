#!/bin/bash
# 지금까지 쌓인 데이터로 규칙 품질을 한 화면에 보여준다.
#
# 공격을 쏘면 재현율이 나오고 정상 워크로드를 돌리면 정밀도가 나온다.
# 둘을 같이 봐야 규칙을 좁힐지 넓힐지 정할 수 있다.
set -euo pipefail
. "$(dirname "$0")/_env.sh"

echo
echo "================ 규칙별 점수판 ================"
echo "  최신 라운드만 본다. 라운드를 섞으면 고친 규칙이 옛 오탐을 지고 간다."
echo "  fp_적어둔것 은 그 시나리오가 조용해야 한다고 미리 적어둔 경우다."
$PSQL -c "SELECT rule_name, tp, fp, fp_적어둔것, 정밀도
          FROM rule_scorecard WHERE tp > 0 OR fp > 0
          ORDER BY 정밀도 NULLS LAST, fp DESC;"

echo "================ 정상 워크로드 판정 ================"
echo "  정상 워크로드에서 규칙이 뜨면 그게 오탐이다. 미리 적어뒀는지는"
echo "  오탐이냐를 가르지 않고 예상했는지만 나타낸다."
$PSQL -c "SELECT result, COALESCE(예상했나, '-') AS 예상했나, COUNT(*) AS 시나리오수
          FROM benign_summary
          WHERE round_id = (SELECT MAX(round_id) FROM benign_log)
          GROUP BY result, 예상했나 ORDER BY result;"

echo "================ 규칙이 뜬 정상 워크로드 ================"
$PSQL -c "SELECT label, kind, rule_name, hits, was_expected_silent AS 조용해야_했나
          FROM false_positives
          WHERE round_id = (SELECT MAX(round_id) FROM benign_log)
          ORDER BY was_expected_silent DESC, hits DESC;"

echo "================ 최근 라운드 종합 ================"
echo "  tp fn fp 는 실행 한 번이 단위다. 잡은기법은 기법이 단위라 뜻이 다르다."
$PSQL -c "SELECT round_id, tp, fn, invalid, fp, tn, fp_예상못함,
                 재현율, 정밀도, f1, 잡은기법, 놓친기법
          FROM overall_metrics ORDER BY round_id DESC LIMIT 5;"
