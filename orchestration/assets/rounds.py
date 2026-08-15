"""라운드 번호를 정하는 asset.

라운드는 루프의 세대다. 공격 실행과 정상 워크로드 실행이 같은 번호를 써야
`overall_metrics` 에서 재현율과 정밀도가 한 줄로 묶인다. 뷰가 round_id 로
조인하기 때문이다.

번호를 고정하면 안 된다. 같은 번호로 두 번 쏘면 채점이 겹쳐 집계된다.
재현율은 그대로인데 건수만 배로 늘어나서, 표를 보고 무엇이 늘었는지 알 수
없게 된다. 그래서 매번 마지막 라운드 + 1 로 올린다.
"""
from __future__ import annotations

import os
import subprocess

from dagster import AssetExecutionContext, Failure, MetadataValue, asset

from . import constants as C

_PROBE = """
import os, sqlalchemy as sa
e = sa.create_engine(os.environ["DATABASE_URL"])
with e.connect() as c:
    print(c.execute(sa.text("select coalesce(max(round_id),0)+1 from execution_log")).scalar_one())
"""


def _env_with_dotenv() -> dict[str, str]:
    """레포 루트의 .env 를 읽어 환경에 얹는다.

    Dagster 를 어떻게 띄웠느냐에 따라 DATABASE_URL 이 없을 수 있다. demo/ 의
    셸 스크립트들은 전부 .env 를 source 해서 쓰므로 같은 출처를 따른다.
    이미 환경에 있는 값은 덮어쓰지 않는다.
    """
    env = dict(os.environ)
    dotenv = C.REPO_ROOT / ".env"
    if not dotenv.exists():
        return env
    for line in dotenv.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env.setdefault(key.strip(), value.strip().strip("'\""))
    return env


@asset
def round_id(context: AssetExecutionContext) -> int:
    """이번 싸이클이 쓸 라운드 번호. 공격과 정상 워크로드가 이 값을 같이 쓴다."""
    cmd = [str(C.VENV_PYTHON), "-c", _PROBE]
    result = subprocess.run(cmd, capture_output=True, text=True, env=_env_with_dotenv())
    if result.returncode != 0:
        raise Failure(
            description="라운드 번호 조회 실패",
            metadata={
                "command": MetadataValue.md(f"`{' '.join(cmd[:2])} ...`"),
                "stderr_tail": result.stderr[-2000:],
            },
        )
    value = int(result.stdout.strip())
    context.log.info(f"이번 라운드는 {value} 다")
    context.add_output_metadata({"round_id": value})
    return value
