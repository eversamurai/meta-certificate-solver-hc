#!/usr/bin/env bash
# Break demo.lab for the demo. Usage: ./lab/break.sh expiring|untrusted|weak|reload
source "$(dirname "$0")/lib.sh"

mode=${1:-}
case "$mode" in
  expiring)
    # step-ca's minimum cert lifetime is 5m; 10m lands well inside the critical window.
    log "installing a lab-CA cert for demo.lab that expires in 10 minutes"
    issue_from_ca demo.lab 10m server
    ;;

  untrusted)
    log "installing a cert for demo.lab signed by a rogue CA nobody trusts"
    ca sh -c 'cd /tmp && rm -f rogue* leaf* &&
      step certificate create "Rogue Corp Root" rogue.crt rogue.key \
        --profile root-ca --no-password --insecure --force >/dev/null &&
      step certificate create demo.lab leaf.crt leaf.key \
        --profile leaf --ca rogue.crt --ca-key rogue.key --san demo.lab \
        --not-after 720h --no-password --insecure --force >/dev/null'
    ca cat /tmp/leaf.crt > "$CERTS/server.crt"
    ca cat /tmp/leaf.key > "$CERTS/server.key"
    ;;

  weak)
    # The CA refuses <2048-bit keys over its API, so sign directly with the intermediate key.
    log "installing a lab-CA cert for demo.lab with a 1024-bit RSA key"
    ca sh -c 'cd /tmp && rm -f leaf* &&
      step certificate create demo.lab leaf.crt leaf.key \
        --profile leaf --kty RSA --size 1024 --san demo.lab --not-after 24h \
        --ca /home/step/certs/intermediate_ca.crt \
        --ca-key /home/step/secrets/intermediate_ca_key \
        --ca-password-file /home/step/secrets/password \
        --no-password --insecure --force >/dev/null &&
      cat leaf.crt /home/step/certs/intermediate_ca.crt > leaf-bundle.crt'
    ca cat /tmp/leaf-bundle.crt > "$CERTS/server.crt"
    ca cat /tmp/leaf.key > "$CERTS/server.key"
    ;;

  reload)
    # Leaves the served cert alone but makes every future reload fail `nginx -t`, like a half-finished
    # config change someone left behind. Run after `weak` for demo case 3: the agent renews, the reload is
    # refused, and it must put the old cert back. ./lab/init.sh removes the snippet.
    mkdir -p "$LAB/conf.d"
    cat > "$LAB/conf.d/zz-legacy.conf" <<'EOF'
# Half-finished migration: nobody added the backend, so `nginx -t` rejects this file.
upstream legacy_backend {
    server legacy.internal:8080 max_fails=three;
}
EOF
    if "${COMPOSE[@]}" exec -T nginx nginx -t -q 2>/dev/null; then
      echo "expected nginx -t to fail, but it passed" >&2
      exit 1
    fi
    log "nginx config is now invalid: reloads will fail, the running workers keep serving"
    log "run a cycle: curl -X POST localhost:8088/api/run"
    exit 0
    ;;

  *)
    echo "usage: $0 expiring|untrusted|weak|reload" >&2
    exit 2
    ;;
esac

reload_nginx
log "demo.lab is now '$mode' — run a cycle: curl -X POST localhost:8088/api/run"
