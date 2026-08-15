# 데모 실행 안내

탐지 규칙 담당 파트 시연용이다. 세 가지를 순서대로 보여준다.

## 0. 환경 확인

랩이 꺼져 있으면 먼저 올린다. 이미 떠 있으면 아무 일도 안 일어난다.

```bash
limactl start purplebpf
limactl shell purplebpf -- docker start tetragon
cd ~/Desktop/security/purplebpf && docker --context lima-purplebpf compose up -d postgres grafana
```

상태 점검.

```bash
limactl shell purplebpf -- docker exec tetragon tetra tracingpolicy list | tail -n +2 | wc -l
```

19가 나와야 한다. 관측 규칙 15개와 대조군 4개다. 차단판은 관측판과 이름이 같아 동시에 올리지 않는다.

## 1. 규칙을 어디에 거느냐로 탐지가 갈린다

```bash
cd ~/Desktop/security/purplebpf && ./demo/run_channel_demo.sh
```

같은 파일을 네 방식으로 읽고 두 규칙이 각각 잡는지 본다. 30초쯤 걸린다. 필요한 파일은 매번 레포에서 VM으로 복사하므로 VM을 껐다 켠 뒤에도 그냥 돌아간다.

```
읽는 방식        baseline     treatment
syscall          잡힘         잡힘
io_uring         놓침         잡힘
io_uring async   놓침         잡힘
mmap             잡힘         놓침
```

io_uring은 시스템콜 진입점을 지나지 않아 baseline이 놓친다. mmap은 읽기가 권한 검사를 지나지 않아 treatment가 놓친다. 서로 다른 사각지대다.

세 번째 줄은 커널 워커에 강제로 넘긴 경우다. 그래도 원래 프로세스로 귀속된다.

## 2. 폐쇄 루프가 실제로 돈다

```bash
cd ~/Desktop/security/purplebpf && ./demo/run_loop_demo.sh
```

약 110초. 규칙을 하나 내리고 공격해서 놓치고, 규칙을 투입하고 다시 공격해서 잡는다.

```
round_id | tp | fn | invalid | 재현율
       9 |  7 |  1 |       1 |  87.5     T1613 규칙 없음
      10 |  8 |  0 |       1 | 100.0     규칙 투입 후

round_id | technique | shots | detects | result
       9 | T1613     |     1 |       0 | FN
      10 | T1613     |     1 |       4 | TP
```

이것이 이 프로젝트의 주장 그 자체다. 놓친 것을 알아내고, 메우고, 메워졌는지 숫자로 확인한다.

한 라운드만 돌리려면 이쪽이다. 약 55초.

```bash
./demo/run_cycle.sh
```

## 3. 대시보드

```
http://127.0.0.1:3000/d/purplebpf-coverage
```

`localhost`가 아니라 `127.0.0.1`이어야 한다. 맥의 3000 포트를 다른 프로그램이 IPv6로 잡고 있어서 `localhost`로 가면 그쪽에 붙는다. lima 포워딩은 IPv4다. 로그인은 없다.

패널은 넷이다. 탐지 성공, 놓침, 측정 불가, 기법별 커버리지, 그리고 라운드별 재현율 추이. 마지막 것에 루프가 도는 모습이 그대로 남는다.

## 나올 만한 질문

오탐률은 왜 없나. 오탐을 정의하려면 공격을 안 쐈을 때 뭐가 뜨는지를 먼저 알아야 하는데 그 기준선을 아직 안 쟀다. 지금 실행과 안 묶이는 탐지가 수천 건 나오는데 그 안에는 시스템의 정상 활동, 우리 도구 자신의 활동, 조인에서 떨어진 진짜 탐지가 섞여 있다. 셋을 못 가르면 오탐이라는 숫자를 못 만든다. 재현율은 정답이 있어서 지금 낼 수 있고 오탐률은 기준선이 없어서 못 낸다. 둘은 필요한 재료가 다르다.

T1611은 왜 INVALID인가. 도커 기본 seccomp가 `unshare`를 CAP_SYS_ADMIN 있는 컨테이너에만 허용한다. Executor 컨테이너에는 그 권한이 없어서 시스템콜 본문이 실행되기 전에 거절된다. 공격이 나가지 않았으니 탐지가 없는 것이 맞다. 이걸 놓친 것으로 세면 있지도 않은 구멍이 다음 라운드 목표로 들어간다. 실측으로 확인했다. seccomp만 풀면 공격은 여전히 실패하지만 규칙은 발화한다.

차단은 왜 하나뿐인가. 차단판은 관측판을 복사해 동작 지시만 붙이면 되는 것이 아니다. setuid에서 확인한 것이 그 예다. 프로세스를 죽이는 방식은 시스템콜이 제 일을 끝낸 뒤에 죽여서 권한 비트가 이미 붙어버렸다. 반환값을 오류로 바꾸는 방식이라야 변경 자체가 일어나지 않았다. 훅마다 같은 확인을 거쳐야 해서 하나씩 늘린다.

## 되돌리기

데이터를 처음 상태로 비우려면.

```bash
docker --context lima-purplebpf compose exec -T postgres \
  psql -U purplebpf -d purplebpf -c "TRUNCATE execution_log, detections;"
```

뷰를 다시 만들려면.

```bash
docker --context lima-purplebpf compose exec -T postgres \
  psql -U purplebpf -d purplebpf < db/views.sql
```
