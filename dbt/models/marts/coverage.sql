{{ config(
    materialized='table',
    post_hook="CREATE OR REPLACE TABLE pg.public.coverage AS SELECT * FROM {{ this }}"
) }}

-- execution_log(뭘 쐈나)와 detections(뭘 잡았나)를 조인해 커버리지를 낸다.
--
-- 조인 조건이 technique 하나뿐이면 안 된다. 같은 기법의 이벤트가 언제 어디서
-- 났든 우리 공격의 탐지로 세어지기 때문이다. 실측으로 T1611 이 TP 로 나왔는데
-- 그 672 건은 전부 runc 가 컨테이너를 만들며 부른 setns/unshare 였다.
-- 우리 공격은 seccomp 에 막혀 실행조차 안 됐다.
--
-- 그래서 세 조건을 더 건다.
--   컨테이너   execution_log 는 Docker short id 12자, detections 는 Tetragon 이 주는
--              31자다. 등호로는 안 맞아서 접두사로 비교한다.
--   시간창     스텝이 도는 동안 난 이벤트만 센다. 뒤쪽 여유는 이벤트 파이프라인
--              지연을 흡수하려는 것이다.
--   실행 성공  success=false 는 공격이 나가지 않은 것이므로 미탐이 아니다.
--              INVALID 로 빼지 않으면 가짜 미탐이 다음 라운드 생성 목표로 되먹여진다.

{% set eps = var('coverage_eps_seconds', 2) %}

WITH shots AS (
  SELECT
    e.run_id,
    e.round_id,
    e.technique,
    e.channel,
    e.success,
    COUNT(d.detection_id) AS hits
  FROM {{ ref('stg_execution_log') }} e
  LEFT JOIN {{ ref('stg_detections') }} d
    ON  d.technique = e.technique
    AND d.container_id LIKE e.container_id || '%'
    AND d.detected_at >= e.started_at
    AND d.detected_at <= e.finished_at + INTERVAL {{ eps }} SECOND
  GROUP BY e.run_id, e.round_id, e.technique, e.channel, e.success
),

-- 어떤 실행 스텝과도 안 묶이는 탐지. 배경 활동이 섞여 있으므로
-- 정온 구간 베이스라인을 재기 전에는 오탐률로 쓸 수 없다.
unmatched AS (
  SELECT d.technique, COUNT(*) AS n
  FROM {{ ref('stg_detections') }} d
  WHERE NOT EXISTS (
    SELECT 1 FROM {{ ref('stg_execution_log') }} e
    WHERE e.technique = d.technique
      AND d.container_id LIKE e.container_id || '%'
      AND d.detected_at >= e.started_at
      AND d.detected_at <= e.finished_at + INTERVAL {{ eps }} SECOND
  )
  GROUP BY d.technique
)

SELECT
  COALESCE(s.technique, u.technique) AS technique,
  COALESCE(MAX(s.round_id), 0) AS round_id,
  COUNT(s.run_id) FILTER (WHERE s.success) AS shots,
  COALESCE(SUM(s.hits), 0) AS detects,
  COUNT(s.run_id) FILTER (WHERE s.success AND s.hits > 0) AS tp,
  COUNT(s.run_id) FILTER (WHERE s.success AND s.hits = 0) AS fn,
  COUNT(s.run_id) FILTER (WHERE NOT s.success) AS invalid,
  COALESCE(MAX(u.n), 0) AS unmatched_detections,
  CASE
    WHEN COUNT(s.run_id) FILTER (WHERE s.success AND s.hits > 0) > 0 THEN 'TP'
    WHEN COUNT(s.run_id) FILTER (WHERE s.success) > 0 THEN 'FN'
    WHEN COUNT(s.run_id) > 0 THEN 'INVALID'
    ELSE 'UNMATCHED'
  END AS result
FROM shots s
FULL OUTER JOIN unmatched u ON u.technique = s.technique
GROUP BY COALESCE(s.technique, u.technique)
ORDER BY technique
