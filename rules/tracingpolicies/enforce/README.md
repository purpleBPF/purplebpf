# 차단판

관측판과 훅·인자·필터가 같고 `matchActions`만 다르다. 같은 규칙 이름을 쓰므로 동시에 올리지 않는다.

## Sigkill 이 아니라 Override 를 쓰는 이유

setuid 규칙에서 실측했다.

```
Sigkill    chmod 가 종료코드 137 로 죽었는데 결과가 -rwsr-xr-x
Override   chmod 가 Operation not permitted, 결과가 -rwxr-xr-x
```

Sigkill 은 시스템콜이 제 일을 끝낸 뒤에 프로세스를 죽인다. 탐지도 되고 프로세스도 죽었는데 막으려던 변경은 이미 일어나 있다. Override 는 커널 함수의 반환값을 오류로 바꿔 변경 자체가 일어나지 않게 한다.

## Override 를 붙일 수 있는 훅

Tetragon 이 직접 알려주는 제약이 있다.

```
override action can be used only with syscalls and security_ hooks
```

실측으로 확인한 결과는 이렇다.

| 훅 | Override | 확인한 것 |
|---|---|---|
| `security_path_chmod` | 막힘 | chmod 실패, 비트 안 붙음 |
| `security_file_open` | 막힘 | cat 이 Operation not permitted |
| `security_file_permission` | 막힘 | 읽기 실패 |
| `security_bprm_check` | 막힘 | 실행 실패 |
| `security_sb_mount` | 막힘 | mount 가 rc=32 |
| `sys_ptrace` | 막힘 | ATTACH 실패 |
| `sys_kill` | 막힘 | 대상이 살아남음 |
| `sys_unshare` | 막힘 | rc=1 |
| `sys_memfd_create` | 막힘 | PermissionError |
| `security_inode_setxattr` | 미확인 | 아래 참고 |
| `unix_stream_connect` | 못 붙임 | security_ 훅도 시스템콜도 아니다 |
| `tcp_connect` | 못 붙임 | 같은 이유 |
| `security_bpf` | 쓰면 안 됨 | 막으면 Tetragon 자신이 eBPF 를 못 써서 죽는다 |

## 만들지 않은 것

| 규칙 | 이유 |
|---|---|
| `exec-file-capability` | 관측판이 이 커널에서 한 번도 안 맞아서 차단 여부를 못 쟀다 |
| `t1552-005-cloud-metadata` | `tcp_connect` 에 Override 를 못 붙인다 |
| `t1610-runtime-socket-connect` | `unix_stream_connect` 에 Override 를 못 붙인다 |
| `t1562-001-defense-tamper` | `security_bpf` 를 막으면 Tetragon 이 죽는다 |
| `t1611-namespace-change` | 조건이 없어 조건 없이 막게 된다 |
| `t1611-host-mount` | 같은 이유 |

앞의 넷은 Tetragon 의 제약이라 다른 방법이 필요하다. 네트워크 차단은 Override 대신 `Sigkill` 을 쓰거나 네트워크 계층에서 막아야 한다. 뒤의 둘은 조건을 좁히면 만들 수 있다.

## 관측판과 조건이 같아야 한다

이름만 다른 두 파일이라 한쪽만 고치면 조용히 어긋난다. 실제로 `t1613` 에서 그랬다. 관측판을 좁혀 오탐을 없앴는데 차단판은 넓은 조건 그대로였다. 그 상태로 올리면 `df` 와 `/sys/fs/cgroup` 읽기까지 막힌다.

어긋나면 대가가 크다. 관측판으로 잰 정밀도가 차단판의 정밀도가 아니게 된다. 오탐 한 건과 정상 동작이 막히는 것은 무게가 다르다.

`matchActions` 를 selector 마다 붙였는지도 봐야 한다. 하나에만 붙이면 나머지 조건은 관측만 하고 안 막는데, 파일이 `enforce/` 아래 있으니 막히는 줄 알게 된다. `t1613` 차단판이 그 상태였다.

둘 다 검사로 남겼다.

```bash
python tests/test_enforce_sync.py
```

## security_inode_setxattr 판정을 보류한 이유

전에 "Override 를 붙여도 rc=0 으로 통과한다" 고 적었는데 그 근거가 성립하지 않는다.

관측판의 인자 번호가 이 커널과 안 맞아서 selector 가 한 번도 안 맞았다. 조건이 안 맞으면 Override 가 실행될 기회 자체가 없다. 그러니 "막는데 안 먹혔다" 와 "애초에 안 걸렸다" 를 구분할 수 없었다.

관측판 인자 번호를 고쳤으므로 다시 재야 한다. 그 전까지 이 줄은 근거로 쓰지 않는다.

## 올릴 때 주의

차단판을 전역으로 올리면 시스템 자체가 마비된다. 실측에서 `t1105` 차단판을 올린 순간 `/tmp` 실행이 막혀 `docker exec` 가 안 됐고, 그러면 Tetragon 을 조작할 수단까지 잃는다. 컨테이너를 다시 띄워야 복구된다.

`t1613` 차단판에도 같은 성질이 있다. 올려두면 `docker run` 이 아예 실패한다.

```
mount callback failed on /tmp/containerd-mount...:
open /tmp/containerd-mount.../.dockerenv: operation not permitted
```

도커가 컨테이너를 만들면서 `/.dockerenv` 를 직접 만들고 여는데, 그것을 정찰로 보고 막기 때문이다. 이미 떠 있는 컨테이너 안에서는 정상 동작(`df`, `ls /sys/fs/cgroup`)이 통과하고 정찰만 막히는 것을 확인했다. 막히는 것은 새 컨테이너 생성뿐이다.

그래서 검증할 때는 컨테이너를 먼저 띄우고 그다음에 차단판을 올린다. 순서가 반대면 대상 컨테이너를 못 만든다.

정책 파일을 `tetragon.tp.d/` 에 두고 시험하지 마라. 그 디렉터리는 재시작 때 자동으로 읽히므로 잘못된 정책을 남겨두면 Tetragon 이 뜨다가 죽는다. 컨테이너 안으로 직접 넣고 끝나면 지운다.

```bash
docker cp rules/tracingpolicies/enforce/<규칙>.yaml tetragon:/tmp/x.yaml
docker exec tetragon tetra tracingpolicy delete <규칙 이름>
docker exec tetragon tetra tracingpolicy add /tmp/x.yaml
# 확인이 끝나면
docker exec tetragon tetra tracingpolicy delete <규칙 이름>
docker exec tetragon tetra tracingpolicy add /etc/tetragon/tetragon.tp.d/<규칙>.yaml
docker exec tetragon rm -f /tmp/x.yaml
```

컨테이너를 한정해서 거는 방법을 찾아봤으나 이 환경에서는 안 된다. `podSelector` 는 쿠버네티스 파드 라벨을 보므로 도커 컨테이너 라벨과 맞지 않는다. `--enable-policy-filter` 를 켜면 정책은 붙지만 라벨 붙은 컨테이너도 안 막힌다.

그래서 지금 차단판은 이렇게 쓴다.

```
용도    규칙이 실제로 막는지 확인할 때만 하나씩 올린다
금지    여러 개를 동시에, 또는 오래 올려두지 않는다
복구    docker restart tetragon
```

측정은 관측판으로 한다. 차단하면 공격이 중간에 죽어 뒷 단계 규칙을 검증할 기회가 사라진다.
