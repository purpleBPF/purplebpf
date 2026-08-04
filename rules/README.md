# PurpleBPF 룰팩

탐지 후보 11종, 정책 파일 17개. 대조실험 6종은 baseline·treatment 두 벌이라 파일 수가 더 많다.

- baseline = 시스템콜 진입점 (`sys_*`). io_uring 경로가 우회하는 쪽
- treatment = 커널 내부 함수 (`security_*`, `tcp_connect`, `unix_stream_connect`)

## 검증 환경

Ubuntu 26.04 / 커널 7.0.0-28-generic / aarch64 / Tetragon v1.7.0 / Docker 29.6.2 (lima VM `purplebpf`)

```
CONFIG_SECURITY_PATH=y      security_path_chmod 사용 가능
CONFIG_BPF_LSM=y            단 부팅 파라미터 lsm= 에 bpf 없음 → tetra probe 의 lsm: false
```

BPF LSM 을 못 쓰므로 전 정책이 kprobe 다. 관리형 쿠버네티스에서도 같은 제약이 흔하므로 이 선택이 배포 가능성 면에서 맞다.

## 검증 결과

`scripts/attack_all.sh` 실행 시 17개 정책 전부 발화 확인.

io_uring 대조실험(01번, 자격증명 파일 읽기)의 2×2:

| | baseline (`sys_openat`) | treatment (`security_file_permission`) |
|---|---|---|
| 일반 read | 잡힘 | 잡힘 |
| io_uring read | 놓침 | 잡힘 |

`scripts/iouring_read.c` 가 `IORING_OP_OPENAT` + `IORING_OP_READ` 로만 파일을 읽어 시스템콜 진입점을 한 번도 거치지 않는다.

## 실측으로 해소된 미확인 항목

io_wq 귀속. `IOSQE_ASYNC` 로 커널 워커 오프로드를 강제한 결과 `pid=10425, tid=10427` 로 갈렸다. tid 는 `iou-wrk-*` 워커이나 pid 는 링 소유 프로세스이고 `binary` 도 원래 바이너리로 찍힌다. 즉 Tetragon 의 `process.pid` 는 tgid 다.

→ 조인은 `process.pid` 로 한다. `process.tid` 로 하면 io_uring 경로에서 전부 미탐이 된다.

`CONFIG_SECURITY_PATH`. 랩 커널에 존재하므로 03번 setuid 정책이 동작한다. 다만 이 옵션이 없는 배포판에서는 kprobe 부착이 실패하므로 룰팩 전제조건으로 명시한다.

## 새로 확인된 제약

`Postfix` 연산자는 `sockaddr_un` 인자에 동작하지 않는다(1.7.0 실측). `Equal` 로 전체 소켓 경로를 나열해야 한다. 08번이 이 때문에 처음에 발화하지 않았다.

`open_flags` 는 1.7.0 의 유효 인자 타입이 아니다. 플래그 필터가 필요하면 `int` 로 받는다.

`tetra` 는 컨테이너 안에서 실행되므로 정책 파일이 `/etc/tetragon/tetragon.tp.d` 에 있어야 읽힌다.

## 알려진 한계 — 오탐

셀렉터가 넓은 정책은 배경 활동을 대량으로 잡는다. 단일 런에서 관측된 건수:

| 정책 | 건수 | 원인 |
|---|---|---|
| 04 tmp-exec | 15,000+ | `/tmp` 접두사가 도구 자신의 파일 접근까지 전부 포함 |
| 07 defense-tamper | 9,000+ | `security_bpf` 는 Tetragon 자신을 포함해 모든 bpf 호출에 반응 |
| 06·08·11 baseline | 각 640 | `sys_connect` 에 셀렉터가 없어 시스템 전체 연결을 수집 |

발화 확인에는 충분하나 이 상태로 오탐률을 보고할 수 없다. 정온 구간 베이스라인 런을 먼저 돌려 배경 프로파일을 만들고, Executor 자신의 흔적을 수집 후 필터링으로 제외해야 한다. `matchBinaries` 로 Executor 를 제외하면 진탐까지 죽으므로 정책이 아니라 후처리에서 건다.

`missed_stats_kprobe: false` 이므로 이벤트 손실 카운터를 이 커널에서 못 쓴다. 손실로 인한 가짜 미탐을 감지할 수단이 없다는 뜻이라 채점 시 유의한다.

## 실행

```bash
limactl start purplebpf
limactl shell purplebpf -- docker start tetragon
# 정책 적재
sudo cp rules/tracingpolicies/*.yaml /etc/tetragon/tetragon.tp.d/
for f in /etc/tetragon/tetragon.tp.d/*.yaml; do docker exec tetragon tetra tracingpolicy add "$f"; done
# 공격 + 집계
docker exec tetragon timeout 35 tetra getevents -o json > /tmp/ev.json &
./scripts/attack_all.sh
python3 scripts/coverage.py /tmp/ev.json /tmp/loaded.txt
```
