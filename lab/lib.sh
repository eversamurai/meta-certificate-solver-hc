# Shared helpers for init.sh and break.sh. Source, don't run.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: don't rewrite /home/step/... into C:/...

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="$LAB/certs"
COMPOSE=(docker compose -f "$LAB/docker-compose.yml")
PW=/home/step/secrets/password

ca()  { "${COMPOSE[@]}" exec -T ca "$@"; }
log() { printf '\033[36m[lab]\033[0m %s\n' "$*"; }

# issue_from_ca NAME DURATION OUT  — leaf+intermediate from the lab CA via the JWK provisioner.
issue_from_ca() {
  local name=$1 dur=$2 out=$3
  ca rm -f /tmp/leaf.crt /tmp/leaf.key
  ca step ca certificate "$name" /tmp/leaf.crt /tmp/leaf.key \
     --provisioner admin --provisioner-password-file "$PW" \
     --not-after "$dur" --force >/dev/null
  ca cat /tmp/leaf.crt > "$CERTS/$out.crt"
  ca cat /tmp/leaf.key > "$CERTS/$out.key"
}

reload_nginx() {
  # Test the config first: a bare `nginx -s reload` exits 0 even when nginx rejects the new config.
  "${COMPOSE[@]}" exec -T nginx sh -c 'nginx -t -q && nginx -s reload' >/dev/null
  log "nginx reloaded"
}
