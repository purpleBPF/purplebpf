"""
PurpleBPF 아키텍처 다이어그램 (diagrams-as-code)
실행: python purplebpf_arch.py  ->  purplebpf_architecture.png 생성
"""
from diagrams import Diagram, Cluster, Edge

from diagrams.onprem.database import Neo4J, Postgresql
from diagrams.onprem.mlops import Mlflow
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.container import Docker
from diagrams.onprem.queue import Kafka            # Redpanda 대역 (전용 아이콘 없음)
from diagrams.onprem.monitoring import Grafana
from diagrams.onprem.analytics import Dbt
from diagrams.onprem.compute import Server         # gemma 대역
from diagrams.programming.framework import Fastapi
from diagrams.programming.language import Python, Bash
from diagrams.programming.flowchart import Document # 룰팩(YAML) 표현
from diagrams.saas.chat import Slack
from diagrams.generic.database import SQL           # DuckDB 대역
from diagrams.generic.storage import Storage        # Iceberg/Parquet 대역
from diagrams.generic.os import LinuxGeneral        # Tetragon/eBPF 대역

graph_attr = {"fontsize": "20", "bgcolor": "white", "splines": "spline"}

with Diagram("PurpleBPF Architecture",
             filename="purplebpf_architecture",
             show=False, direction="LR", graph_attr=graph_attr):

    # ================= ① 벤더 룰 팩토리 (내부 인프라 · Dagster 오케스트레이션) =================
    with Cluster("① 벤더 룰 팩토리  (내부 · Dagster 오케스트레이션)"):

        with Cluster("생성 (Offensive)"):
            kg      = Neo4J("Neo4j\n(ATT&CK KG)")
            gemma   = Server("gemma\n(Ollama/vLLM)")
            mlflow  = Mlflow("MLflow")
            filt    = Bash("1차 필터\n(shellcheck+룰엔진)")
            slack   = Slack("2차 검수")
            api     = Fastapi("FastAPI\n(콜백)")
            queue   = Redis("Redis\n(잡큐+캐시)")
            execu   = Docker("Executor")

            kg >> gemma >> filt >> slack >> api >> queue >> execu
            gemma >> Edge(style="dotted") >> mlflow

        with Cluster("방어 (Defensive)"):
            tetragon = LinuxGeneral("Tetragon\n(eBPF)")
            redpanda = Kafka("Redpanda\n(이벤트 버퍼)")
            mapper   = Python("Mapper\n(태깅)")
            rulepack = Document("TracingPolicy 룰팩\n(재우·희수)")

            tetragon >> Edge(label="gRPC") >> redpanda >> mapper
            rulepack >> Edge(label="rules", color="firebrick") >> tetragon

        with Cluster("데이터 (OLTP / OLAP)"):
            pg      = Postgresql("Postgres\n(OLTP: 메타·상태)")
            lake    = Storage("Iceberg/Parquet\n(OLAP: detections)")
            duckdb  = SQL("DuckDB\n(조인 엔진)")

            pg >> duckdb
            lake >> duckdb

        with Cluster("분석 (Metrics)"):
            dbt_    = Dbt("dbt\n(지표·정합성)")
            grafana = Grafana("Grafana\n(커버리지 히트맵)")
            duckdb >> dbt_ >> grafana

        # --- 경계: 두 채널로 발사 (technique × channel) ---
        execu >> Edge(label="syscall / io_uring", color="darkorange", fontcolor="darkorange") >> tetragon

        # --- 정답/예측 적재 ---
        execu >> Edge(label="y_true", color="blue") >> pg
        mapper >> Edge(label="y_pred", color="green") >> lake

        # --- 피드백 루프 (FN 재투입) ---
        duckdb >> Edge(label="FN → 재겨냥", color="red", style="dashed") >> gemma
        duckdb >> Edge(label="FN → 룰 보강", color="red", style="dashed") >> rulepack

    # ================= ② 고객사 배포 (경량 에이전트) =================
    with Cluster("② 고객사 배포  (보안팀 없는 스타트업/중소기업)"):
        cust_agent = LinuxGeneral("Tetragon\n경량 에이전트")
        cust_rules = Document("갱신 룰팩\n(배포본)")
        cust_rules >> cust_agent

    # 내부 룰팩 -> 고객 배포
    rulepack >> Edge(label="배포", color="firebrick", style="bold") >> cust_rules