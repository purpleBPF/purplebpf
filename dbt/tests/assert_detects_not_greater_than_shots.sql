-- 잡은 게(detects) 쏜 것(shots)보다 많으면 조인 버그다.
-- FP(shots=0, 실행 없이 탐지만 있는 행)는 예외로 둔다.
SELECT *
FROM {{ ref('coverage') }}
WHERE NOT (detects <= shots OR shots = 0)
