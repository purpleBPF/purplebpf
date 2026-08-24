"""
PurpleBPF 아키텍처 다이어그램 v2 (diagrams-as-code)

v1(purplebpf_architecture.py) 대비 실제 스택에 맞춰 다시 그린 버전이다.
- Redis 잡큐 / Redpanda 이벤트버퍼 / MLflow 제거: docker-compose.yml(postgres·neo4j·
  grafana만 include), pyproject.toml 의존성, mapper.py 어디에도 없다. Mapper는
  Tetragon 이벤트를 Postgres에 직접 쓴다(중간 브로커 없음).
- Validator Level1~3 추가: v1은 "1차 필터"만 그렸지만, 실제 방어 게이트는
  1차 필터(구조·syntax·순서) 통과 후 RULE_VALIDATOR(Level1 shell syntax /
  Level2 bashlex 기반 CLI 인자 분석 / Level3 MITRE ATT&CK 기법 의미 매칭)를
  한 번 더 거친다(executor.py의 _validate_execution_gate).
- Lima VM ↔ Mac Host 분리 추가: 공격 실행 프로세스(1차필터→Validator→Executor)와
  Mapper·Tetragon은 Lima VM(`purplebpf`) 안에서 돈다. Neo4j·Ollama·Postgres·
  Dagster·DuckDB·dbt·Grafana는 Mac Host에서 돈다. VM은 host.lima.internal로
  host 서비스에 접속한다 — 이게 필요한 이유는 Docker Desktop이 아니라 진짜
  Linux 커널이 있어야 Tetragon(eBPF)이 syscall을 관측할 수 있기 때문이다.
- Slack 콜백은 "표시 전용"임을 라벨로 명시: 버튼을 눌러도 execute_chain이나
  execution_log 갱신으로 이어지지 않는다(slack_callback.py 확인 완료, 별도 과제).

실행:
    pip install diagrams   (레포 의존성 아님 — 다이어그램 그릴 때만 필요)
    python architecture_logo/purplebpf_architecture_v2.py
    -> purplebpf_architecture_v2.png (전체)
    -> purplebpf_architecture_v2_offense.png (공격층)
    -> purplebpf_architecture_v2_middle.png  (중간층 · 측정/오케스트레이션)
    -> purplebpf_architecture_v2_defense.png (방어층)
"""
from diagrams import Diagram, Cluster, Edge

from diagrams.onprem.database import Neo4J, Postgresql
from diagrams.onprem.container import Docker
from diagrams.onprem.monitoring import Grafana
from diagrams.onprem.analytics import Dbt
from diagrams.onprem.compute import Server           # Ollama(gemma) 대역
from diagrams.programming.framework import Fastapi
from diagrams.programming.language import Python, Bash
from diagrams.programming.flowchart import Document  # 룰팩(YAML) 등 파일 표현 전용
from diagrams.saas.chat import Slack
from diagrams.generic.database import SQL            # DuckDB 대역
from diagrams.generic.storage import Storage          # Iceberg/Parquet 대역
from diagrams.generic.os import LinuxGeneral          # Tetragon/Lima VM 대역
from diagrams.generic.compute import Rack             # Dagster 대역

GRAPH_ATTR = {
    "fontsize": "20",
    "bgcolor": "white",
    "splines": "spline",
    "nodesep": "0.6",
    "ranksep": "0.9",
}


# ============================================================================
# ① 전체 개요 — Lima VM / Mac Host 경계를 축으로 세 층(공격·방어·중간)을 배치
# ============================================================================
with Diagram(
    "PurpleBPF Architecture v2",
    filename="purplebpf_architecture_v2",
    show=False,
    direction="LR",
    graph_attr=GRAPH_ATTR,
):
    with Cluster("🐧 Lima VM 'purplebpf'  (실제 Linux 커널 · eBPF 관측 가능)"):
        with Cluster("공격층 (Offensive) — 1회성 프로세스"):
            filt = Bash("1차 필터\n(구조·shellcheck·순서)")
            val = Python("Validator L1-3\n(syntax/bashlex/ATT&CK 매칭)")
            execu = Docker("Executor\n(일회용 컨테이너)")
            filt >> val >> execu

        with Cluster("방어층 (Defensive) — 상시 데몬"):
            tetragon = LinuxGeneral("Tetragon\n(eBPF, TracingPolicy)")
            mapper = Python("Mapper\n(rule_mapping.yaml 태깅)")
            tetragon >> Edge(label="tetra getevents") >> mapper

        execu >> Edge(label="syscall / io_uring", color="darkorange", fontcolor="darkorange") >> tetragon

    with Cluster("🖥 Mac Host"):
        with Cluster("공격층 — 백엔드 서비스"):
            kg = Neo4J("Neo4j\n(ATT&CK KG)")
            gemma = Server("gemma\n(Ollama)")
            slack = Slack("Slack\n(2차 검수 웹훅)")
            callback = Fastapi("Slack 콜백\n(표시 전용, 미연결)")
            slack >> Edge(style="dashed", label="버튼 클릭") >> callback

        with Cluster("중간층 (Middle) — 측정 · 오케스트레이션"):
            dagster = Rack("Dagster\n(에셋 오케스트레이션)")
            pg = Postgresql("Postgres\n(OLTP: execution_log·detections)")
            lake = Storage("Iceberg/Parquet\n(로컬 SQLite 카탈로그)")
            duckdb = SQL("DuckDB\n(Postgres+Iceberg 조인)")
            dbt_ = Dbt("dbt-duckdb\n(coverage·recall_by_round)")
            grafana = Grafana("Grafana")

            dagster >> Edge(label="① 트리거") >> pg
            pg >> Edge(label="detections만 동기화") >> lake
            pg >> duckdb
            lake >> duckdb
            duckdb >> dbt_ >> Edge(label="write back") >> pg
            pg >> grafana

    # --- VM ↔ Host 네트워크 경계 (host.lima.internal) ---
    dagster >> Edge(label="limactl shell 트리거", color="purple") >> filt
    kg >> Edge(style="dotted", label="host.lima.internal", color="gray") >> val
    gemma >> Edge(style="dotted", label="host.lima.internal", color="gray") >> filt
    val >> Edge(style="dashed", label="REVIEW 시") >> slack
    execu >> Edge(label="y_true", color="blue") >> pg
    mapper >> Edge(label="y_pred", color="green", style="dotted") >> pg

    # --- 관찰 기반 재겨냥 (사람이 Grafana/대시보드 보고 TARGET_TECHNIQUE_ID 조정) ---
    grafana >> Edge(label="FN 관찰 → 사람이 재겨냥", color="red", style="dashed") >> kg


# ============================================================================
# ② 공격층 (Offensive) 상세
# ============================================================================
with Diagram(
    "PurpleBPF Architecture v2 — 공격층",
    filename="purplebpf_architecture_v2_offense",
    show=False,
    direction="LR",
    graph_attr=GRAPH_ATTR,
):
    with Cluster("지식그래프 (Mac Host)"):
        kg = Neo4J("Neo4j\n(ATT&CK STIX)")

    with Cluster("생성 (Lima VM 프로세스 → Mac Host 서비스 호출)"):
        gemma = Server("gemma\n(Ollama, host)")
        retriever = Python("retriever.py\n(GraphRAG 서브그래프)")
        kg >> retriever >> gemma

    with Cluster("검증 게이트 (Lima VM, executor.main())"):
        filt = Bash("1차 필터\n(structure·syntax·ordering)")
        v1 = Python("Level1\n(shell 문법)")
        v2 = Python("Level2\n(bashlex CLI 인자 분석)")
        v3 = Python("Level3\n(ATT&CK 기법 의미 매칭)")
        gemma >> filt >> v1 >> v2 >> v3

    with Cluster("사람 개입 (human-in-the-loop)"):
        slack = Slack("Slack 2차 검수\n(REVIEW 시 웹훅)")
        callback = Fastapi("Slack 콜백\n(표시 전용 — 실행과 미연결)")
        slack >> Edge(style="dashed") >> callback

    v2 >> Edge(label="REVIEW", color="orange") >> slack
    v3 >> Edge(label="REVIEW", color="orange") >> slack

    with Cluster("실행 (Lima VM 실제 Docker)"):
        execu = Docker("Executor\n(일회용 컨테이너, --privileged 금지)")
    v3 >> Edge(label="PASS (또는 --allow-review)", color="green") >> execu

    execu >> Edge(
        label="exit 0=성공 2=REJECT 3=REVIEW\n(둘 다 Dagster 정상완주) 1/4/5=실패",
        color="black",
    ) >> Document("execution_log\n기록 여부는\n결정에 따라 분기")


# ============================================================================
# ③ 중간층 (Middle) 상세 — 측정 · 오케스트레이션 (전부 Mac Host)
# ============================================================================
with Diagram(
    "PurpleBPF Architecture v2 — 중간층",
    filename="purplebpf_architecture_v2_middle",
    show=False,
    direction="LR",
    graph_attr=GRAPH_ATTR,
):
    with Cluster("오케스트레이션 (Dagster)"):
        dagster = Rack("coverage_loop\nrun_attack_round →\nsync_iceberg →\nrun_coverage_dbt →\ntest_coverage_dbt")

        with Cluster("독립 asset"):
            dashboard = Fastapi("render_attack_dashboard\n(HTML 생성 + 브라우저 오픈)")

    with Cluster("OLTP"):
        pg = Postgresql("Postgres\nexecution_log · detections")

    with Cluster("OLAP"):
        lake = Storage("Iceberg/Parquet\n(로컬 SQLite 카탈로그,\ndetections만 동기화)")
        duckdb = SQL("DuckDB\n(pg ATTACH + Iceberg 조인)")

    with Cluster("변환 · 시각화"):
        dbt_ = Dbt("dbt-duckdb\nstaging → marts")
        grafana = Grafana("Grafana")

    dashboard >> Edge(style="dashed", color="gray", label="컴퓨트 로그 읽기 전용") >> dagster
    dagster >> Edge(label="① 공격 실행 트리거") >> pg
    pg >> Edge(label="② detections 동기화") >> lake
    pg >> duckdb
    lake >> duckdb
    duckdb >> Edge(label="③ coverage/recall_by_round") >> dbt_
    dbt_ >> Edge(label="write back (post_hook)") >> pg
    pg >> grafana
    dagster >> dashboard


# ============================================================================
# ④ 방어층 (Defensive) 상세 — 전부 Lima VM 상시 데몬
# ============================================================================
with Diagram(
    "PurpleBPF Architecture v2 — 방어층",
    filename="purplebpf_architecture_v2_defense",
    show=False,
    direction="LR",
    graph_attr=GRAPH_ATTR,
):
    with Cluster("Lima VM 'purplebpf' — 상시 데몬 (Dagster 밖)"):
        rules = Document(
            "TracingPolicy 룰팩\n(enforce 1·observe 9·experiments 4)"
        )
        tetragon = LinuxGeneral("Tetragon (eBPF)\nkprobe 기반\n(BPF LSM 미탑재 환경)")
        stream = Bash("tetra getevents -o json")
        mapper = Python("Mapper\n(rule_mapping.yaml로\npolicy_name → technique 태깅)")

        rules >> Edge(label="정책 로드", color="firebrick") >> tetragon
        tetragon >> stream >> mapper

    with Cluster("Mac Host"):
        pg = Postgresql("Postgres\ndetections 테이블")

    mapper >> Edge(
        label="직접 INSERT (host.lima.internal:5433)\n※ Redpanda/Kafka 브로커 없음",
        color="green",
    ) >> pg

    with Cluster("② 고객사 배포 (경량 에이전트, 개념)"):
        cust_rules = Document("갱신 룰팩\n(배포본)")
        cust_agent = LinuxGeneral("Tetragon\n경량 에이전트")
        cust_rules >> cust_agent

    rules >> Edge(label="③ 배포", color="firebrick", style="bold", minlen="2") >> cust_rules
