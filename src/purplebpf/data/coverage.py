"""execution_log(뭘 쐈나) ⋈ detections(뭘 잡았나) → TP / FN / FP.

Mapper 가 detections 에 run_id 를 NULL 로 넣으므로 조인 키는
(container_id, technique, 시간창) 이다. 시간창은 스텝의 started_at 부터
finished_at + EPS 까지다.

한계 두 가지를 알고 써야 한다.

  1. io_uring 비동기 작업은 io_uring_enter 리턴 뒤에 이벤트가 나올 수 있어
     시간창을 벗어난다. 그때는 실제로 탐지했는데 FN 으로 계상된다.
     난수 마커를 두 테이블에 컬럼으로 넣으면 없어지는 문제다.
  2. success=false 인 스텝은 공격이 실제로 실행되지 않은 것이므로
     FN 이 아니라 INVALID 다. 여기 섞으면 가짜 FN 이 생성기로 되먹여진다.

사용법:
    python -m purplebpf.data.coverage            # 최신 라운드
    python -m purplebpf.data.coverage --round 2
"""
from __future__ import annotations

import argparse

from sqlalchemy import text

from purplebpf.common.config import build_db_engine

# 탐지 이벤트가 스텝 종료 직후에 도착하는 여유. io_wq 오프로드와
# 이벤트 파이프라인 지연을 흡수한다.
EPS_SECONDS = 2

JOIN_SQL = text(
    """
    SELECT
        e.run_id,
        e.technique,
        e.channel,
        e.success,
        COUNT(d.detection_id) AS hits
    FROM execution_log e
    LEFT JOIN detections d
      -- Executor 는 Docker short_id(12자)를, Tetragon 은 더 긴 컨테이너 ID를 준다.
      -- 짧은 쪽이 긴 쪽의 접두사이므로 prefix 로 맞춘다. 등호로 두면 항상 어긋난다.
      ON  d.container_id LIKE e.container_id || '%'
      AND d.technique    = e.technique
      AND d.detected_at >= e.started_at
      AND d.detected_at <= e.finished_at + (:eps || ' seconds')::interval
    WHERE e.round_id = :round_id
    GROUP BY e.run_id, e.technique, e.channel, e.success
    ORDER BY e.technique, e.run_id
    """
)

# 어떤 실행 스텝과도 안 묶이는 탐지. 정온 구간 베이스라인이 없으면
# 이 숫자는 배경 활동까지 포함하므로 그대로 오탐률로 쓰면 안 된다.
FP_SQL = text(
    """
    SELECT d.technique, COUNT(*) AS n
    FROM detections d
    WHERE NOT EXISTS (
        SELECT 1 FROM execution_log e
        WHERE d.container_id LIKE e.container_id || '%'
          AND e.technique    = d.technique
          AND d.detected_at >= e.started_at
          AND d.detected_at <= e.finished_at + (:eps || ' seconds')::interval
    )
    GROUP BY d.technique
    ORDER BY n DESC
    """
)

LATEST_ROUND_SQL = text("SELECT COALESCE(MAX(round_id), 1) FROM execution_log")


def main() -> None:
    ap = argparse.ArgumentParser(description="탐지 커버리지(TP/FN/FP) 산출")
    ap.add_argument("--round", type=int, help="라운드 번호 (기본: 최신)")
    ap.add_argument("--eps", type=int, default=EPS_SECONDS, help="시간창 여유(초)")
    args = ap.parse_args()

    engine = build_db_engine()
    with engine.connect() as conn:
        round_id = args.round or conn.execute(LATEST_ROUND_SQL).scalar_one()
        rows = conn.execute(JOIN_SQL, {"round_id": round_id, "eps": args.eps}).mappings().all()
        fps = conn.execute(FP_SQL, {"eps": args.eps}).mappings().all()

    if not rows:
        print(f"라운드 {round_id} 에 실행 기록이 없다.")
        return

    tp = [r for r in rows if r["success"] and r["hits"] > 0]
    fn = [r for r in rows if r["success"] and r["hits"] == 0]
    invalid = [r for r in rows if not r["success"]]

    print(f"=== 라운드 {round_id} 커버리지 (시간창 여유 {args.eps}초) ===\n")
    print(f"{'기법':<12} {'채널':<10} {'판정':<8} 탐지건수")
    for r in rows:
        verdict = "INVALID" if not r["success"] else ("TP" if r["hits"] else "FN")
        print(f"{r['technique']:<12} {r['channel']:<10} {verdict:<8} {r['hits']}")

    total = len(tp) + len(fn)
    recall = f"{len(tp) / total:.1%}" if total else "계산 불가"
    print(f"\nTP {len(tp)}  FN {len(fn)}  INVALID {len(invalid)}")
    print(f"재현율 {recall}   (INVALID 는 분모에서 제외)")

    if fn:
        print("\n놓친 기법 — 다음 라운드 생성 목표")
        for r in fn:
            print(f"  {r['technique']} ({r['channel']})")

    if fps:
        print("\n실행과 안 묶인 탐지 (오탐 후보)")
        for r in fps:
            print(f"  {r['technique']:<12} {r['n']}")
        print("  정온 구간 베이스라인 없이는 오탐률로 쓸 수 없다.")


if __name__ == "__main__":
    main()
