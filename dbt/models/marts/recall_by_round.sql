{{ config(
    materialized='table',
    post_hook="CREATE OR REPLACE TABLE pg.public.recall_by_round AS SELECT * FROM {{ this }}"
) }}

-- coverage.sql과 동일한 조인/판정 기준(technique + container_id 접두사 + 시간창)을
-- 그대로 재사용하되, GROUP BY만 technique 대신 round_id로 바꿔 라운드별
-- tp/fn/invalid/recall_pct를 낸다. coverage.sql과 다른 recall이 나오면 안 되므로
-- 판정 로직(성공 여부, hits>0 기준)은 절대 바꾸지 않는다.

{% set eps = var('coverage_eps_seconds', 2) %}

WITH shots AS (
  SELECT
    e.run_id,
    e.round_id,
    e.success,
    COUNT(d.detection_id) AS hits
  FROM {{ ref('stg_execution_log') }} e
  LEFT JOIN {{ ref('stg_detections') }} d
    ON  d.technique = e.technique
    AND d.container_id LIKE e.container_id || '%'
    AND (d.detected_at AT TIME ZONE 'UTC') >= e.started_at
    AND (d.detected_at AT TIME ZONE 'UTC') <= e.finished_at + INTERVAL {{ eps }} SECOND
  GROUP BY e.run_id, e.round_id, e.success
)

SELECT
  round_id,
  COUNT(run_id) FILTER (WHERE success AND hits > 0) AS tp,
  COUNT(run_id) FILTER (WHERE success AND hits = 0) AS fn,
  COUNT(run_id) FILTER (WHERE NOT success) AS invalid,
  CASE
    WHEN COUNT(run_id) FILTER (WHERE success AND hits > 0)
       + COUNT(run_id) FILTER (WHERE success AND hits = 0) = 0
    THEN NULL
    ELSE ROUND(
      100.0 * COUNT(run_id) FILTER (WHERE success AND hits > 0)
      / (COUNT(run_id) FILTER (WHERE success AND hits > 0)
       + COUNT(run_id) FILTER (WHERE success AND hits = 0)),
      1
    )
  END AS recall_pct
FROM shots
GROUP BY round_id
ORDER BY round_id
