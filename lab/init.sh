#!/usr/bin/env bash
# Bring the lab up from scratch (or reset it): CA, root export, healthy certs, nginx.
source "$(dirname "$0")/lib.sh"

mkdir -p "$CERTS" "$LAB/webroot/.well-known/acme-challenge"

log "starting step-ca"
"${COMPOSE[@]}" up -d --wait ca

log "exporting root CA -> lab/certs/root_ca.crt (the agent trusts this)"
ca cat /home/step/certs/root_ca.crt > "$CERTS/root_ca.crt"

log "issuing healthy 24h cert for demo.lab"
issue_from_ca demo.lab 24h server
log "issuing 4h cert for shop.prod (inside the warn window, so the agent wants to act)"
issue_from_ca shop.prod 4h prod

log "starting nginx"
"${COMPOSE[@]}" up -d --force-recreate nginx

log "ready: https://localhost:8443 (demo.lab, lab)  https://localhost:8444 (shop.prod, prod)"
log "ACME directory: https://localhost:9000/acme/acme/directory"
