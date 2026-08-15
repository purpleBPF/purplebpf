"""coverage.py 의 조인 로직을 sqlite 로 검증한다.

Postgres 없이 돌아가야 CI 에서 쓸 수 있으므로, 같은 조인 조건을
sqlite 문법으로 옮겨 판정만 확인한다. Postgres 쪽 쿼리는 interval
문법만 다르고 조인 조건은 동일하다.

python3 tests/test_coverage_sql.py
"""

import sqlite3

SCHEMA = """
CREATE TABLE execution_log (
    run_id INTEGER PRIMARY KEY, round_id INT, technique TEXT, channel TEXT,
    success INT, started_at TEXT, finished_at TEXT, container_id TEXT);
CREATE TABLE detections (
    detection_id INTEGER PRIMARY KEY, technique TEXT, rule_name TEXT,
    detected_at TEXT, container_id TEXT);
"""

# coverage.py 의 JOIN_SQL 과 같은 조인 조건 (interval 만 sqlite 문법)
JOIN = """
SELECT e.technique, e.channel, e.success, COUNT(d.detection_id) AS hits
FROM execution_log e
LEFT JOIN detections d
  ON  d.container_id = e.container_id
  AND d.technique    = e.technique
  AND d.detected_at >= e.started_at
  AND d.detected_at <= datetime(e.finished_at, '+2 seconds')
WHERE e.round_id = 1
GROUP BY e.run_id, e.technique, e.channel, e.success
ORDER BY e.technique
"""


def verdict(row):
    _, _, success, hits = row
    return "INVALID" if not success else ("TP" if hits else "FN")


def main():
    db = sqlite3.connect(":memory:")
    db.executescript(SCHEMA)

    # 쐈다: 3건. 성공 2건 + 실패 1건
    db.executemany(
        "INSERT INTO execution_log VALUES (?,?,?,?,?,?,?,?)",
        [
            (1, 1, "T1548.001", "syscall",  1, "2026-08-06 12:00:00", "2026-08-06 12:00:01", "abc"),
            (2, 1, "T1552.001", "io_uring", 1, "2026-08-06 12:00:10", "2026-08-06 12:00:11", "abc"),
            (3, 1, "T1611",     "syscall",  0, "2026-08-06 12:00:20", "2026-08-06 12:00:21", "abc"),
        ],
    )
    # 잡았다: T1548.001 만. 시간창 안.
    db.executemany(
        "INSERT INTO detections VALUES (?,?,?,?,?)",
        [
            (1, "T1548.001", "t1548-001-setuid-bit-set", "2026-08-06 12:00:01", "abc"),
            # 시간창 밖 (30초 뒤) — 묶이면 안 된다
            (2, "T1552.001", "t1552-001-cred-file-read", "2026-08-06 12:00:41", "abc"),
            # 다른 컨테이너 — 묶이면 안 된다
            (3, "T1611",     "t1611-namespace-change",   "2026-08-06 12:00:20", "zzz"),
        ],
    )

    rows = db.execute(JOIN).fetchall()
    got = {r[0]: verdict(r) for r in rows}

    assert got["T1548.001"] == "TP", got        # 시간창 안에서 잡힘
    assert got["T1552.001"] == "FN", got        # 탐지는 있으나 시간창 밖
    assert got["T1611"] == "INVALID", got       # 실행 실패라 FN 이 아니다

    # 재현율은 INVALID 를 분모에서 뺀다
    tp = sum(1 for r in rows if verdict(r) == "TP")
    fn = sum(1 for r in rows if verdict(r) == "FN")
    assert (tp, fn) == (1, 1) and tp / (tp + fn) == 0.5, (tp, fn)

    print("ok", got)


if __name__ == "__main__":
    main()
