-- 커버리지 뷰. Grafana 대시보드가 이것을 읽는다.
--
-- dbt 로 만드는 coverage 마트와 목적이 같지만 경로가 다르다. dbt 쪽은
-- detections 를 Iceberg 에서 읽는데 현재 Mapper 는 Postgres 에 쓴다.
-- 그래서 데모 경로에서는 Postgres 안에서 뷰로 끝낸다. 뷰라서 싸이클을
-- 돌릴 때마다 자동으로 최신이 된다.
--
-- 적용: docker compose exec -T postgres psql -U purplebpf -d purplebpf < db/views.sql

DROP VIEW IF EXISTS coverage CASCADE;
DROP VIEW IF EXISTS recall_by_round CASCADE;
DROP VIEW IF EXISTS coverage_by_round CASCADE;

-- 라운드별 기법별 판정.
--
-- 조인 조건이 technique 하나뿐이면 안 된다. 같은 기법의 이벤트가 언제
-- 어디서 났든 우리 공격의 탐지로 세어지기 때문이다. 실측으로 T1611 이
-- TP 로 나왔는데 그 672 건은 전부 runc 가 컨테이너를 만들며 부른
-- setns/unshare 였다. 우리 공격은 seccomp 에 막혀 실행조차 안 됐다.
--
--   컨테이너   execution_log 는 Docker short id 12자, detections 는
--              Tetragon 이 주는 31자다. 등호로는 안 맞아 접두사로 비교한다.
--   시간창     스텝이 도는 동안 난 이벤트만 센다. 뒤쪽 2초는 이벤트
--              파이프라인 지연을 흡수하려는 것이다.
--   실행 성공  success=false 는 공격이 나가지 않은 것이므로 미탐이 아니다.
--              INVALID 로 빼지 않으면 가짜 미탐이 다음 라운드 생성 목표로
--              되먹여져 루프가 있지도 않은 구멍을 판다.
CREATE VIEW coverage_by_round AS
WITH shots AS (
  SELECT e.run_id, e.round_id, e.technique, e.success,
         COUNT(d.detection_id) AS hits
  FROM execution_log e
  LEFT JOIN detections d
    ON  d.technique = e.technique
    AND d.container_id LIKE e.container_id || '%'
    AND d.detected_at >= e.started_at
    AND d.detected_at <= e.finished_at + interval '2 seconds'
  GROUP BY e.run_id, e.round_id, e.technique, e.success
)
SELECT round_id, technique,
       COUNT(*) FILTER (WHERE success)               AS shots,
       COALESCE(SUM(hits), 0)                        AS detects,
       CASE WHEN COUNT(*) FILTER (WHERE success AND hits > 0) > 0 THEN 'TP'
            WHEN COUNT(*) FILTER (WHERE success) > 0                THEN 'FN'
            ELSE 'INVALID' END                       AS result
FROM shots
GROUP BY round_id, technique;

-- 대시보드가 읽는 뷰. 항상 최신 라운드만 보여준다.
CREATE VIEW coverage AS
SELECT technique, shots, detects, result, round_id
FROM coverage_by_round
WHERE round_id = (SELECT MAX(round_id) FROM execution_log);

-- 라운드별 재현율. 루프가 도는 것이 이 표에서 보인다.
-- INVALID 는 분모에서 뺀다. 실행이 안 된 것을 놓친 것으로 세면 안 된다.
CREATE VIEW recall_by_round AS
SELECT round_id,
       COUNT(*) FILTER (WHERE result = 'TP')      AS tp,
       COUNT(*) FILTER (WHERE result = 'FN')      AS fn,
       COUNT(*) FILTER (WHERE result = 'INVALID') AS invalid,
       ROUND(100.0 * COUNT(*) FILTER (WHERE result = 'TP')
             / NULLIF(COUNT(*) FILTER (WHERE result IN ('TP','FN')), 0), 1) AS recall_pct
FROM coverage_by_round
GROUP BY round_id
ORDER BY round_id;

-- ============================================================
-- 오탐 측정
-- ============================================================
--
-- 정상 워크로드를 돌리는 동안 규칙이 뜨면 그게 오탐이다.
-- 조인 조건은 커버리지와 같다. 컨테이너 접두사와 시간창.
-- 다만 technique 으로는 못 잇는다. 정상 워크로드에는 기법이 없다.
--
-- expect_silent 에 적힌 규칙이 떴으면 확정 오탐이다.
-- 거기 없는 규칙이 떴으면 그 워크로드가 건드릴 줄 몰랐던 것이므로
-- 별도로 표시한다. 규칙을 다시 봐야 한다는 신호다.

DROP VIEW IF EXISTS false_positives CASCADE;
DROP VIEW IF EXISTS benign_summary CASCADE;

CREATE VIEW false_positives AS
SELECT
  b.round_id,
  b.label,
  b.kind,
  d.rule_name,
  d.technique,
  COUNT(*) AS hits,
  -- rule_name 은 varchar, expect_silent 는 text[] 라 형을 맞춰야 한다.
  d.rule_name::text = ANY(b.expect_silent) AS was_expected_silent
FROM benign_log b
JOIN detections d
  ON  d.container_id LIKE b.container_id || '%'
  AND d.detected_at >= b.started_at
  AND d.detected_at <= b.finished_at + interval '2 seconds'
GROUP BY b.round_id, b.label, b.kind, d.rule_name, d.technique, b.expect_silent;

-- 시나리오별 요약.
--
-- 정상 워크로드에서 규칙이 뜨면 그게 오탐이다. 미리 적어뒀는지는 오탐이냐
-- 아니냐를 가르지 않는다.
--
-- 예전에는 expect_silent 에 적힌 것만 FP 로 세고 나머지는 UNEXPECTED 로 뒀다.
-- 그러면 뜰 걸 알면서 안 적기만 하면 정밀도가 안 떨어진다. 실제로 규칙 셋이
-- 그렇게 분모 밖으로 나가 라운드 24 정밀도가 100% 로 나왔다. 아는 오탐을
-- 모르는 칸으로 옮긴 것이라 고쳤다.
--
-- 적어뒀는지는 따로 남긴다. 그건 오탐이냐가 아니라 내가 예상했느냐다.
--   declared    좁혔다고 생각한 규칙이 여전히 뜬다. 트랩이 제 일을 했다
--   undeclared  건드릴 줄 몰랐던 규칙이 떴다. 규칙을 다시 봐야 한다
CREATE VIEW benign_summary AS
SELECT
  b.round_id,
  b.label,
  b.kind,
  COALESCE(f.total_hits, 0) AS 발화건수,
  COALESCE(f.violated, 0)   AS 적어둔_규칙이_뜬_수,
  CASE WHEN COALESCE(f.total_hits, 0) > 0 THEN 'FP' ELSE 'CLEAN' END AS result,
  CASE WHEN COALESCE(f.total_hits, 0) = 0 THEN NULL
       WHEN COALESCE(f.violated, 0) > 0   THEN 'declared'
       ELSE 'undeclared' END AS 예상했나
FROM benign_log b
LEFT JOIN (
  SELECT round_id, label,
         SUM(hits) AS total_hits,
         COUNT(*) FILTER (WHERE was_expected_silent) AS violated
  FROM false_positives GROUP BY round_id, label
) f ON f.round_id = b.round_id AND f.label = b.label;

-- ============================================================
-- 종합 평가
-- ============================================================
--
-- 여기서 세는 단위는 실행 한 번이다. 기법이 아니다.
--
-- 예전에는 재현율의 분자를 기법 수로, 정밀도의 분모를 시나리오 수로 썼다.
-- 서로 다른 것을 더한 값이라 정밀도가 뜻을 갖지 못했다. 기법 12개 중 11개를
-- 잡았다와 시나리오 3개에서 잘못 떴다를 11/(11+3) 으로 나누면 그 숫자는
-- 아무것도 아니다.
--
-- 그래서 양쪽을 실행 단위로 맞췄다. 공격을 한 번 실행한 것과 정상 워크로드를
-- 한 번 실행한 것은 둘 다 "한 번 돌렸고 경보가 떴거나 안 떴다" 라서 같이 셀 수 있다.
--
-- 기법 단위 커버리지는 없앤 게 아니라 recall_by_round 에 그대로 있다.
-- 묻는 게 다르다. 저기는 어느 기법을 덮느냐이고 여기는 뜬 경보 중 진짜가
-- 얼마냐다. 둘을 한 칸에 섞지 않는다.

DROP VIEW IF EXISTS rule_scorecard CASCADE;
DROP VIEW IF EXISTS overall_metrics CASCADE;

-- 규칙별 점수판. 어느 규칙을 고쳐야 하는지 여기서 정해진다.
--
-- 라운드로 가른다. 안 가르면 tp 는 1라운드부터 누적되는데 fp 는 정상
-- 워크로드를 돌린 라운드에만 있어서 정밀도가 실제보다 높게 나온다.
-- 라운드 사이에 규칙 파일이 바뀌기도 하므로, 안 가르면 서로 다른 버전
-- 규칙의 성적이 한 줄에 합산된다. 고친 규칙이 옛 오탐을 지고 가고
-- 망가뜨린 규칙이 옛 tp 에 가려진다.
CREATE VIEW rule_scorecard_by_round AS
WITH tp AS (
  SELECT e.round_id, d.rule_name, COUNT(DISTINCT e.run_id) AS tp
  FROM execution_log e
  JOIN detections d
    ON  d.technique = e.technique
    AND d.container_id LIKE e.container_id || '%'
    AND d.detected_at BETWEEN e.started_at AND e.finished_at + interval '2 seconds'
  WHERE e.success
  GROUP BY e.round_id, d.rule_name
),
fp AS (
  SELECT b.round_id, d.rule_name,
         COUNT(DISTINCT b.run_id) AS fp_scenarios,
         COUNT(*) AS fp_hits,
         COUNT(DISTINCT b.run_id) FILTER (WHERE d.rule_name::text = ANY(b.expect_silent))
           AS fp_declared
  FROM benign_log b
  JOIN detections d
    ON  d.container_id LIKE b.container_id || '%'
    AND d.detected_at BETWEEN b.started_at AND b.finished_at + interval '2 seconds'
  GROUP BY b.round_id, d.rule_name
)
SELECT COALESCE(tp.round_id, fp.round_id)   AS round_id,
       COALESCE(tp.rule_name, fp.rule_name) AS rule_name,
       COALESCE(tp.tp, 0)            AS tp,
       COALESCE(fp.fp_scenarios, 0)  AS fp,
       COALESCE(fp.fp_declared, 0)   AS fp_적어둔것,
       COALESCE(fp.fp_hits, 0)       AS fp_이벤트수,
       ROUND(100.0 * COALESCE(tp.tp, 0)
             / NULLIF(COALESCE(tp.tp, 0) + COALESCE(fp.fp_scenarios, 0), 0), 1) AS 정밀도
FROM tp FULL OUTER JOIN fp
  ON fp.rule_name = tp.rule_name AND fp.round_id = tp.round_id;

-- 화면이 읽는 뷰. 항상 최신 라운드만 보여준다.
CREATE VIEW rule_scorecard AS
SELECT * FROM rule_scorecard_by_round
WHERE round_id = (SELECT MAX(round_id) FROM execution_log)
ORDER BY fp DESC, rule_name;

-- 라운드 전체 지표. 공격 라운드와 정상 라운드가 짝일 때만 정밀도가 나온다.
--
-- 공격 실행 하나가 하나의 경보 기회다. 탐지가 하나라도 붙으면 잡은 것,
-- 안 붙으면 놓친 것. 실행 자체가 실패한 것(success=false)은 공격이 나가지
-- 않은 것이므로 양쪽 어디에도 안 넣는다.
CREATE VIEW overall_metrics AS
WITH shot AS (
  SELECT e.round_id, e.run_id,
         COUNT(d.detection_id) > 0 AS caught
  FROM execution_log e
  LEFT JOIN detections d
    ON  d.technique = e.technique
    AND d.container_id LIKE e.container_id || '%'
    AND d.detected_at >= e.started_at
    AND d.detected_at <= e.finished_at + interval '2 seconds'
  WHERE e.success
  GROUP BY e.round_id, e.run_id
),
a AS (
  SELECT round_id,
         COUNT(*) FILTER (WHERE caught)     AS tp,
         COUNT(*) FILTER (WHERE NOT caught) AS fn
  FROM shot GROUP BY round_id
),
inv AS (
  SELECT round_id, COUNT(*) AS invalid
  FROM execution_log WHERE NOT success GROUP BY round_id
),
b AS (
  SELECT round_id,
         COUNT(*) FILTER (WHERE result = 'FP')    AS fp,
         COUNT(*) FILTER (WHERE result = 'CLEAN') AS tn,
         COUNT(*) FILTER (WHERE 예상했나 = 'undeclared') AS fp_예상못함
  FROM benign_summary GROUP BY round_id
),
cov AS (
  SELECT round_id, tp AS 잡은기법, fn AS 놓친기법
  FROM recall_by_round
)
SELECT COALESCE(a.round_id, b.round_id, inv.round_id) AS round_id,
       COALESCE(a.tp, 0) AS tp, COALESCE(a.fn, 0) AS fn,
       COALESCE(inv.invalid, 0) AS invalid,
       COALESCE(b.fp, 0) AS fp, COALESCE(b.tn, 0) AS tn,
       COALESCE(b.fp_예상못함, 0) AS fp_예상못함,
       ROUND(100.0 * a.tp / NULLIF(a.tp + a.fn, 0), 1)   AS 재현율,
       ROUND(100.0 * a.tp / NULLIF(a.tp + b.fp, 0), 1)   AS 정밀도,
       ROUND(200.0 * a.tp / NULLIF(2 * a.tp + a.fn + b.fp, 0), 1) AS f1,
       -- 기법 단위 커버리지. 위의 실행 단위 숫자와 뜻이 다르니 따로 둔다.
       cov.잡은기법, cov.놓친기법
FROM a
FULL OUTER JOIN b   ON b.round_id   = a.round_id
FULL OUTER JOIN inv ON inv.round_id = COALESCE(a.round_id, b.round_id)
LEFT JOIN cov       ON cov.round_id = COALESCE(a.round_id, b.round_id, inv.round_id)
ORDER BY 1;
