"""Dagster 진입점. `dagster dev -f orchestration/definitions.py`로 띄운다.

스케줄/센서는 없다 — UI에서 "Materialize all"을 누르거나 CLI로 직접
`dagster asset materialize`를 실행했을 때만 파이프라인이 돈다.
"""
from dagster import Definitions, load_assets_from_modules

from orchestration.assets import chain_dashboard, coverage_loop

defs = Definitions(assets=load_assets_from_modules([coverage_loop, chain_dashboard]))
