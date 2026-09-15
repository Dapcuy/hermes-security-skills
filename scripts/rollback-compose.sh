#!/usr/bin/env bash
# Controlled rollback to a previously verified immutable proxy image.
# Usage: rollback-compose.sh <registry/image@sha256:digest>
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[^/@[:space:]]+(/[^@[:space:]]+)+@sha256:[0-9a-f]{64}$ ]]; then
  printf 'rollback: require fully-qualified image@sha256:<64 lowercase hex>\n' >&2
  exit 2
fi
: "${HERMES_BUNDLE_SHA256:?HERMES_BUNDLE_SHA256 is required}"
: "${HERMES_POLICY_DIR:?HERMES_POLICY_DIR is required}"
: "${COSIGN_BIN:=cosign}"
: "${COSIGN_KEY:?COSIGN_KEY is required for rollback verification}"
: "${COMPOSE_FILE:=deploy/compose/production.yaml}"

image_ref="$1"
if [[ "$COSIGN_KEY" == env://* || "$COSIGN_KEY" == https://* || "$COSIGN_KEY" == file://* ]]; then
  key_ref="$COSIGN_KEY"
else
  key_ref="$COSIGN_KEY"
fi
"$COSIGN_BIN" verify --key "$key_ref" --insecure-ignore-tlog "$image_ref" >/dev/null

export HERMES_PROXY_IMAGE="$image_ref"
docker compose -f "$COMPOSE_FILE" config >/dev/null
docker compose -f "$COMPOSE_FILE" up -d hermes-proxy >/dev/null

container_id=$(docker compose -f "$COMPOSE_FILE" ps -q hermes-proxy)
test -n "$container_id"
for _ in $(seq 1 30); do
  digest_match=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$container_id" | grep -Fx "$image_ref" || true)
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$container_id")
  [[ -n "$digest_match" && "$status" == healthy ]] && exit 0
  [[ "$status" == unhealthy ]] && { printf 'rollback: proxy unhealthy\n' >&2; exit 1; }
  sleep 2
done
printf 'rollback: readiness timeout\n' >&2
exit 1
