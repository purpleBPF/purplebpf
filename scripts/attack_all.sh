#!/bin/bash
# 룰팩 11종 전체를 발화시키는 최소 공격 묶음. 전부 무해하고 teardown 포함.
# 각 스텝은 난수 마커 사이에 감싸서 이벤트 스트림에서 구간을 자를 수 있게 한다.
NONCE=${NONCE:-$(cat /proc/sys/kernel/random/uuid)}
M=/tmp/pbpf/$NONCE
mkdir -p "$M"
mark() { touch "$M/$1"; cat "$M/$1" >/dev/null; }

mark 01.begin
sudo cat /root/.ssh/id_rsa >/dev/null 2>&1
sudo /tmp/iouring_read /root/.ssh/id_rsa >/dev/null 2>&1      # io_uring 레그
mark 01.end

mark 02.begin
sudo unshare --mount --user --map-root-user true 2>/dev/null
mark 02.end

mark 03.begin
cp /bin/true /tmp/pbpf-suid && sudo chmod 4755 /tmp/pbpf-suid
mark 03.end

mark 04.begin
cp /bin/true /tmp/pbpf-dropped && /tmp/pbpf-dropped
mark 04.end

mark 06.begin
curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1
mark 06.end

mark 07.begin
sudo kill -0 1 2>/dev/null                                     # sys_kill
sudo bpftool prog list >/dev/null 2>&1 || true                 # security_bpf
mark 07.end

mark 08.begin
sudo curl -s --max-time 2 --unix-socket /var/run/docker.sock http://localhost/version >/dev/null 2>&1
mark 08.end

mark 09.begin
sudo mkdir -p /tmp/pbpf-mnt && sudo mount --bind /etc /tmp/pbpf-mnt && sudo umount /tmp/pbpf-mnt
mark 09.end

mark 10.begin
sudo python3 -c "
import os
fd = os.memfd_create('pbpf')
os.write(fd, open('/bin/true','rb').read())
pid = os.fork()
if pid == 0:
    os.execv(f'/proc/self/fd/{fd}', ['pbpf-memfd'])
os.waitpid(pid, 0)
" 2>/dev/null
mark 10.end

# teardown
sudo rm -f /tmp/pbpf-suid /tmp/pbpf-dropped
sudo rmdir /tmp/pbpf-mnt 2>/dev/null
echo "NONCE=$NONCE"
