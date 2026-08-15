"""공격→탐지→측정 파이프라인의 경로/VM/환경변수 상수.

팀원 로컬 환경(Lima VM 이름, 레포 경로 등)이 다르면 이 파일만 고치면 된다.
환경변수로도 덮어쓸 수 있게 해서, 코드를 건드리지 않고도 팀원별로 값을 바꿀 수 있다
(레포에서 이미 쓰는 PBPF_RULE_MAPPING 같은 관례를 따름).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

# --- 호스트(맥) 측 경로. REPO_ROOT는 이 파일 위치 기준으로 계산되므로,
# 레포를 어디에 clone하든(팀원 경로가 달라도) 그대로 맞는다. ---
REPO_ROOT = Path(__file__).resolve().parents[2]
VENV_PYTHON = Path(os.environ.get("PBPF_VENV_PYTHON", REPO_ROOT / ".venv" / "bin" / "python"))
VENV_DBT = Path(os.environ.get("PBPF_VENV_DBT", REPO_ROOT / ".venv" / "bin" / "dbt"))
DBT_PROJECT_DIR = Path(os.environ.get("PBPF_DBT_PROJECT_DIR", REPO_ROOT / "dbt"))
DBT_PROFILES_DIR = Path(os.environ.get("PBPF_DBT_PROFILES_DIR", REPO_ROOT / "dbt"))

# --- Lima VM 측 ---
# VM 이름은 사람마다 다르다("default", "purplebpf"). 켜져 있는 VM 이 하나뿐이면
# 그것을 쓰고, 여러 개면 판단하지 않고 PBPF_LIMA_VM 을 요구한다.


def _detect_lima_vm() -> str:
    try:
        out = subprocess.run(
            ["limactl", "list", "--format", "{{.Name}} {{.Status}}"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return "default"
    running = [ln.split()[0] for ln in out.splitlines() if ln.strip().endswith("Running")]
    if len(running) == 1:
        return running[0]
    return "default"


LIMA_VM_NAME = os.environ.get("PBPF_LIMA_VM") or _detect_lima_vm()

# lima 는 맥 홈 디렉터리를 VM 안에 같은 경로로 마운트한다. 그래서 레포를 어디에
# clone 했든 VM 에서 보이는 경로가 호스트 경로와 같다. 팀원별로 고칠 필요가 없다.
VM_REPO_ROOT = os.environ.get("PBPF_VM_REPO_ROOT", str(REPO_ROOT))
VM_ENV_FILE = os.environ.get("PBPF_VM_ENV_FILE", "~/purplebpf.env")

# 탐지 수집(Mapper)을 어디서 돌릴지.
#   vm    VM 안에서 돈다. VM 에 psycopg2/sqlalchemy/pyyaml 이 깔려 있어야 한다.
#   host  이벤트만 VM 에서 받아 파이프로 넘기고 Mapper 는 맥의 .venv 로 돈다.
# VM 에 파이썬 의존성을 안 깐 환경에서는 host 를 쓴다. demo/run_cycle.sh 가 이 방식이다.
MAPPER_LOCATION = os.environ.get("PBPF_MAPPER_LOCATION", "vm")

# --- 파이프라인 파라미터 ---
TARGET_TECHNIQUE_ID = os.environ.get("PBPF_TARGET_TECHNIQUE", "T1059.004")
DETECTION_WINDOW_SECONDS = int(os.environ.get("PBPF_DETECTION_WINDOW_SECONDS", "10"))

# 정상 워크로드(오탐 측정용) 시나리오. 공격과 짝을 이뤄야 정밀도가 나온다.
BENIGN_SCENARIO_DIR = Path(os.environ.get("PBPF_BENIGN_DIR", REPO_ROOT / "demo" / "benign"))
BENIGN_WINDOW_SECONDS = int(os.environ.get("PBPF_BENIGN_WINDOW_SECONDS", "600"))
