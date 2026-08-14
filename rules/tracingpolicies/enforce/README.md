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
| `security_inode_setxattr` | 안 막힘 | 정책은 붙는데 rc=0 으로 통과 |
| `unix_stream_connect` | 못 붙임 | security_ 훅도 시스템콜도 아니다 |
| `tcp_connect` | 못 붙임 | 같은 이유 |
| `security_bpf` | 쓰면 안 됨 | 막으면 Tetragon 자신이 eBPF 를 못 써서 죽는다 |

## 만들지 않은 것

| 규칙 | 이유 |
|---|---|
| `exec-file-capability` | `security_inode_setxattr` 가 Override 를 받아도 안 막힌다 |
| `t1552-005-cloud-metadata` | `tcp_connect` 에 Override 를 못 붙인다 |
| `t1610-runtime-socket-connect` | `unix_stream_connect` 에 Override 를 못 붙인다 |
| `t1562-001-defense-tamper` | `security_bpf` 를 막으면 Tetragon 이 죽는다 |
| `t1611-namespace-change` | 조건이 없어 조건 없이 막게 된다 |
| `t1611-host-mount` | 같은 이유 |

앞의 넷은 Tetragon 의 제약이라 다른 방법이 필요하다. 네트워크 차단은 Override 대신 `Sigkill` 을 쓰거나 네트워크 계층에서 막아야 한다. 뒤의 둘은 조건을 좁히면 만들 수 있다.

## 올릴 때 주의

차단판을 전역으로 올리면 시스템 자체가 마비된다. 실측에서 `t1105` 차단판을 올린 순간 `/tmp` 실행이 막혀 `docker exec` 가 안 됐고, 그러면 Tetragon 을 조작할 수단까지 잃는다. 컨테이너를 다시 띄워야 복구된다.

컨테이너를 한정해서 거는 방법을 찾아봤으나 이 환경에서는 안 된다. `podSelector` 는 쿠버네티스 파드 라벨을 보므로 도커 컨테이너 라벨과 맞지 않는다. `--enable-policy-filter` 를 켜면 정책은 붙지만 라벨 붙은 컨테이너도 안 막힌다.

그래서 지금 차단판은 이렇게 쓴다.

```
용도    규칙이 실제로 막는지 확인할 때만 하나씩 올린다
금지    여러 개를 동시에, 또는 오래 올려두지 않는다
복구    docker restart tetragon
```

측정은 관측판으로 한다. 차단하면 공격이 중간에 죽어 뒷 단계 규칙을 검증할 기회가 사라진다.
