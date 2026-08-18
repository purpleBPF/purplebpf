"""공격→탐지→측정 파이프라인의 경로/VM/환경변수 상수.

팀원 로컬 환경(Lima VM 이름, 레포 경로 등)이 다르면 이 파일만 고치면 된다.
환경변수로도 덮어쓸 수 있게 해서, 코드를 건드리지 않고도 팀원별로 값을 바꿀 수 있다
(레포에서 이미 쓰는 PBPF_RULE_MAPPING 같은 관례를 따름).
"""
from __future__ import annotations

import os
from pathlib import Path

# --- 호스트(맥) 측 경로. REPO_ROOT는 이 파일 위치 기준으로 계산되므로,
# 레포를 어디에 clone하든(팀원 경로가 달라도) 그대로 맞는다. ---
REPO_ROOT = Path(__file__).resolve().parents[2]
VENV_PYTHON = Path(os.environ.get("PBPF_VENV_PYTHON", REPO_ROOT / ".venv" / "bin" / "python"))
VENV_DBT = Path(os.environ.get("PBPF_VENV_DBT", REPO_ROOT / ".venv" / "bin" / "dbt"))
DBT_PROJECT_DIR = Path(os.environ.get("PBPF_DBT_PROJECT_DIR", REPO_ROOT / "dbt"))
DBT_PROFILES_DIR = Path(os.environ.get("PBPF_DBT_PROFILES_DIR", REPO_ROOT / "dbt"))

# --- Lima VM 측. 호스트에서는 알 수 없는 값들이라 상수/환경변수로만 관리한다. ---
# `limactl list`로 실제 VM 이름을 확인할 것. demo/ 스크립트들은 "purplebpf"를 쓰지만
# 이 저장소가 실제로 물려있는 VM은 "default"였다 — 팀원 환경에 맞춰 바꿀 것.
LIMA_VM_NAME = os.environ.get("PBPF_LIMA_VM", "default")
VM_REPO_ROOT = os.environ.get("PBPF_VM_REPO_ROOT", "/Users/kwonjunhui/Desktop/PurpleBPF")
VM_ENV_FILE = os.environ.get("PBPF_VM_ENV_FILE", "~/purplebpf.env")

# --- 파이프라인 파라미터 ---
TARGET_TECHNIQUE_ID = os.environ.get("PBPF_TARGET_TECHNIQUE", "T1059.004")
