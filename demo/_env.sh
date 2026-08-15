# demo/ 스크립트들이 공통으로 쓰는 환경. source 해서 쓴다.
#
# VM 이름과 도커 소켓 경로가 사람마다 다르다. 스크립트마다 적어두면 팀원이
# 받았을 때 전부 고쳐야 하므로 여기 한 곳에서 정한다.
#
#   PBPF_LIMA_VM   VM 이름을 직접 지정한다. 안 주면 켜져 있는 VM 이 하나일 때
#                  그것을 쓰고, 여러 개면 어느 것인지 판단하지 않고 멈춘다.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

set -a; . ./.env; set +a
export PYTHONPATH=src           # editable install 의 .pth 가 처리 안 되는 환경 대비
PY=.venv/bin/python

if [ -z "${PBPF_LIMA_VM:-}" ]; then
  RUNNING=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null \
            | awk '$2=="Running"{print $1}')
  case $(echo "$RUNNING" | grep -c .) in
    1) PBPF_LIMA_VM=$RUNNING ;;
    0) echo "켜져 있는 lima VM 이 없다. limactl start <이름> 으로 띄운다." >&2; exit 1 ;;
    *) echo "켜져 있는 VM 이 여럿이다. PBPF_LIMA_VM 으로 지정한다:" >&2
       echo "$RUNNING" | sed 's/^/  /' >&2; exit 1 ;;
  esac
fi
export PBPF_LIMA_VM

export DOCKER_HOST="unix://$HOME/.lima/$PBPF_LIMA_VM/sock/docker.sock"
DOCKER_CTX="lima-$PBPF_LIMA_VM"
PSQL="docker --context $DOCKER_CTX compose exec -T postgres psql -U purplebpf -d purplebpf"
