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
