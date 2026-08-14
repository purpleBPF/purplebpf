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

-- 시나리오별 요약. 조용해야 할 것이 조용했는지 본다.
CREATE VIEW benign_summary AS
SELECT
  b.round_id,
  b.label,
  b.kind,
  COALESCE(f.total_hits, 0) AS 발화건수,
  COALESCE(f.violated, 0)   AS 조용해야_하는데_뜬_규칙수,
  CASE WHEN COALESCE(f.violated, 0) > 0 THEN 'FP'
       WHEN COALESCE(f.total_hits, 0) > 0 THEN 'UNEXPECTED'
       ELSE 'CLEAN' END AS result
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
-- 공격 실행에서 TP 와 FN 이, 정상 실행에서 FP 가 나온다.
-- 둘을 합쳐야 정밀도와 F1 을 낼 수 있다.
--
-- 주의: 재현율과 정밀도의 분모가 다르다. 재현율은 쏜 공격 중 몇 개를
-- 잡았나이고, 정밀도는 뜬 탐지 중 몇 개가 진짜였나다. 정상 워크로드를
-- 안 돌린 라운드는 정밀도가 안 나온다.

DROP VIEW IF EXISTS rule_scorecard CASCADE;
DROP VIEW IF EXISTS overall_metrics CASCADE;

-- 규칙별 점수판. 어느 규칙을 고쳐야 하는지 여기서 정해진다.
CREATE VIEW rule_scorecard AS
WITH tp AS (
  SELECT d.rule_name, COUNT(DISTINCT e.run_id) AS tp
  FROM execution_log e
  JOIN detections d
    ON  d.technique = e.technique
    AND d.container_id LIKE e.container_id || '%'
    AND d.detected_at BETWEEN e.started_at AND e.finished_at + interval '2 seconds'
  WHERE e.success
  GROUP BY d.rule_name
),
fp AS (
  SELECT d.rule_name,
         COUNT(DISTINCT b.run_id) AS fp_scenarios,
         COUNT(*) AS fp_hits,
         COUNT(DISTINCT b.run_id) FILTER (WHERE d.rule_name::text = ANY(b.expect_silent))
           AS fp_declared
  FROM benign_log b
  JOIN detections d
    ON  d.container_id LIKE b.container_id || '%'
    AND d.detected_at BETWEEN b.started_at AND b.finished_at + interval '2 seconds'
  GROUP BY d.rule_name
)
SELECT COALESCE(tp.rule_name, fp.rule_name) AS rule_name,
       COALESCE(tp.tp, 0)            AS tp,
       COALESCE(fp.fp_scenarios, 0)  AS fp,
       COALESCE(fp.fp_declared, 0)   AS fp_확정,
       COALESCE(fp.fp_hits, 0)       AS fp_이벤트수,
       ROUND(100.0 * COALESCE(tp.tp, 0)
             / NULLIF(COALESCE(tp.tp, 0) + COALESCE(fp.fp_scenarios, 0), 0), 1) AS 정밀도
FROM tp FULL OUTER JOIN fp ON fp.rule_name = tp.rule_name
ORDER BY COALESCE(fp.fp_scenarios, 0) DESC, rule_name;

-- 라운드 전체 지표. 공격 라운드와 정상 라운드가 짝일 때만 정밀도가 나온다.
CREATE VIEW overall_metrics AS
WITH a AS (
  SELECT round_id,
         COUNT(*) FILTER (WHERE result = 'TP')      AS tp,
         COUNT(*) FILTER (WHERE result = 'FN')      AS fn,
         COUNT(*) FILTER (WHERE result = 'INVALID') AS invalid
  FROM coverage_by_round GROUP BY round_id
),
b AS (
  SELECT round_id,
         COUNT(*) FILTER (WHERE result = 'FP')         AS fp,
         COUNT(*) FILTER (WHERE result = 'CLEAN')      AS tn,
         COUNT(*) FILTER (WHERE result = 'UNEXPECTED') AS unexpected
  FROM benign_summary GROUP BY round_id
)
SELECT COALESCE(a.round_id, b.round_id) AS round_id,
       COALESCE(a.tp, 0) AS tp, COALESCE(a.fn, 0) AS fn,
       COALESCE(a.invalid, 0) AS invalid,
       COALESCE(b.fp, 0) AS fp, COALESCE(b.tn, 0) AS tn,
       COALESCE(b.unexpected, 0) AS unexpected,
       ROUND(100.0 * a.tp / NULLIF(a.tp + a.fn, 0), 1)   AS 재현율,
       ROUND(100.0 * a.tp / NULLIF(a.tp + b.fp, 0), 1)   AS 정밀도,
       ROUND(200.0 * a.tp / NULLIF(2 * a.tp + a.fn + b.fp, 0), 1) AS f1
FROM a FULL OUTER JOIN b ON b.round_id = a.round_id
ORDER BY 1;
