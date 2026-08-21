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
--
-- 시간창 비교에서 d.detected_at 은 반드시 AT TIME ZONE 'UTC' 로 감싼다.
-- detections(Iceberg)는 iceberg_setup.py의 _to_naive_utc() 때문에 타임존 없는
-- TIMESTAMP 로 온다(내용물은 UTC). execution_log(Postgres, ATTACH)는
-- TIMESTAMPTZ 다. 캐스팅 없이 그냥 비교하면 DuckDB가 naive 쪽을 세션
-- 타임존(TimeZone 설정, 기본은 로컬 OS 타임존) 기준 로컬시각으로 암시적
-- 캐스팅해버려서, 세션 타임존이 UTC가 아닌 환경에서는 같은 순간인데도
-- 어긋나게 비교되어 조인이 통째로 실패한다(실측: KST 환경에서 9시간
-- 어긋나 detects=0). AT TIME ZONE 'UTC' 로 "이 naive 값은 UTC"라고 명시하면
-- 세션 타임존과 무관하게 항상 같은 결과가 나온다.

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
    AND (d.detected_at AT TIME ZONE 'UTC') >= e.started_at
    AND (d.detected_at AT TIME ZONE 'UTC') <= e.finished_at + INTERVAL {{ eps }} SECOND
  GROUP BY e.run_id, e.round_id, e.technique, e.channel, e.success
),

-- 어떤 "성공한" 실행과도 안 묶이는 탐지. 배경 활동이 섞여 있으므로
-- 정온 구간 베이스라인을 재기 전에는 오탐률로 쓸 수 없다.
--
-- invalid(success=false) 실행 주변에서 난 탐지도 여기 포함한다. 공격이
-- 나가지 않았으니 그 탐지는 이 공격이 잡은 게 아니다 — shots 쪽에서
-- invalid를 미탐(FN)이 아니라 별도로 빼는 것과 같은 이유다. e.success 조건이
-- 없으면 invalid 실행에 우연히 묶인 탐지가 matched 취급돼 detects 에도
-- unmatched 에도 안 잡히고 조용히 사라진다.
unmatched AS (
  SELECT d.technique, COUNT(*) AS n
  FROM {{ ref('stg_detections') }} d
  WHERE NOT EXISTS (
    SELECT 1 FROM {{ ref('stg_execution_log') }} e
    WHERE e.technique = d.technique
      AND e.success
      AND d.container_id LIKE e.container_id || '%'
      AND (d.detected_at AT TIME ZONE 'UTC') >= e.started_at
      AND (d.detected_at AT TIME ZONE 'UTC') <= e.finished_at + INTERVAL {{ eps }} SECOND
  )
  GROUP BY d.technique
)

-- detects는 "탐지된 공격 수"다 — shots/tp/fn/invalid와 같은 단위(run_id 개수)로
-- 맞춘다. 한 공격에 detection 이벤트가 몇 개 매칭되든(예: 서버->bash->정찰명령
-- 각 프로세스가 다 하나씩 이벤트를 냄) 공격 하나당 1로만 센다 — 그래서
-- 정의상 tp와 같은 값이 된다("탐지된 공격 수"라는 정의가 하나뿐이라서 우연이
-- 아니다). invalid 실행에 우연히 매칭된 이벤트는 s.success 필터로 제외되므로
-- detects에 안 섞인다(그 이벤트들은 위 unmatched로 옮겨간다). 컬럼 자체는
-- Grafana/coverage_history가 이름을 참조하므로 남겨둔다.
SELECT
  COALESCE(s.technique, u.technique) AS technique,
  COALESCE(MAX(s.round_id), 0) AS round_id,
  COUNT(s.run_id) FILTER (WHERE s.success) AS shots,
  COUNT(s.run_id) FILTER (WHERE s.success AND s.hits > 0) AS detects,
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
