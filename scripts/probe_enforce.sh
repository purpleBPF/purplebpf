#!/bin/bash
# 훅마다 Override 가 실제로 동작을 막는지 확인한다.
#
# 문서만 보고는 알 수 없다. setuid 에서 Sigkill 이 프로세스는 죽였는데
# 권한 비트는 이미 붙어버린 일이 있었다. 훅마다 커널이 그 지점을 지난
# 뒤에 무엇을 하느냐가 달라서, 돌려봐야 안다.
#
# 각 훅에 대해 세 가지를 본다.
#   정책이 로드되는가
#   동작이 실패하는가 (반환값)
#   실제 결과가 안 바뀌었는가 (부수효과)
set -u
TPD=/etc/tetragon/tetragon.tp.d
POL=probe-enforce

load() {  # load <call> <syscall여부> <args yaml> <selectors yaml>
  sudo tee $TPD/$POL.yaml >/dev/null <<EOF
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "$POL"
spec:
  kprobes:
  - call: "$1"
    syscall: $2
$3
$4
EOF
  docker exec tetragon tetra tracingpolicy delete $POL >/dev/null 2>&1
  docker exec tetragon tetra tracingpolicy add $TPD/$POL.yaml 2>&1 | tail -1
}

unload() {
  docker exec tetragon tetra tracingpolicy delete $POL >/dev/null 2>&1
  sudo rm -f $TPD/$POL.yaml
}

echo "### security_path_chmod (기준. 이미 되는 것으로 아는 훅)"
load "security_path_chmod" "false" \
'    args:
    - index: 0
      type: "path"
    - index: 1
      type: "int"' \
'    selectors:
    - matchArgs:
      - index: 1
        operator: "Mask"
        values: [ "2048" ]
      matchActions:
      - action: Override
        argError: -1'
rm -f /tmp/pe && cp /bin/true /tmp/pe
chmod 4755 /tmp/pe 2>&1 | tail -1
echo "  결과 권한: $(stat -c %A /tmp/pe)"
unload

echo
echo "### security_file_open (파일 열기 차단)"
load "security_file_open" "false" \
'    args:
    - index: 0
      type: "file"' \
'    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values: [ "/tmp/pe-open" ]
      matchActions:
      - action: Override
        argError: -1'
echo canary > /tmp/pe-open
echo "  읽기 시도: $(cat /tmp/pe-open 2>&1 | tail -1)"
unload

echo
echo "### security_bprm_check (실행 차단)"
load "security_bprm_check" "false" \
'    args:
    - index: 0
      type: "linux_binprm"' \
'    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values: [ "/tmp/pe-exec" ]
      matchActions:
      - action: Override
        argError: -1'
cp /bin/true /tmp/pe-exec
echo "  실행 시도: $(/tmp/pe-exec 2>&1 | tail -1; echo rc=$?)"
unload

echo
echo "### sys_ptrace (시스템콜 차단)"
load "sys_ptrace" "true" \
'    args:
    - index: 0
      type: "int"' \
'    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values: [ "16" ]
      matchActions:
      - action: Override
        argError: -1'
echo "  ptrace 시도: $(perl -e 'my $p=fork(); if($p==0){sleep 5;exit} sleep 1; my $r=syscall(117,16,$p,0,0); print $r==0?"성공":"차단됨($!)"; kill 9,$p' 2>&1 | tail -1)"
unload

echo
echo "### sys_kill (시그널 차단)"
load "sys_kill" "true" \
'    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"' \
'    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values: [ "15" ]
      matchActions:
      - action: Override
        argError: -1'
sleep 30 & TARGET=$!
sleep 0.3
kill -15 $TARGET 2>&1 | tail -1
sleep 0.3
kill -0 $TARGET 2>/dev/null && echo "  대상 살아있음 (차단 성공)" || echo "  대상 죽음 (차단 실패)"
kill -9 $TARGET 2>/dev/null
unload

rm -f /tmp/pe /tmp/pe-open /tmp/pe-exec
