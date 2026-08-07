{{ config(
    materialized='table',
    post_hook="CREATE OR REPLACE TABLE pg.public.coverage AS SELECT * FROM {{ this }}"
) }}

SELECT
  COALESCE(e.technique, d.technique) AS technique,
  COUNT(DISTINCT e.run_id) AS shots,
  COUNT(DISTINCT d.detection_id) AS detects,
  CASE
    WHEN COUNT(e.run_id) > 0 AND COUNT(d.detection_id) > 0 THEN 'TP'
    WHEN COUNT(e.run_id) > 0 AND COUNT(d.detection_id) = 0 THEN 'FN'
    ELSE 'FP'
  END AS result
FROM {{ ref('stg_execution_log') }} e
FULL OUTER JOIN {{ ref('stg_detections') }} d ON e.technique = d.technique
GROUP BY COALESCE(e.technique, d.technique)
ORDER BY technique
