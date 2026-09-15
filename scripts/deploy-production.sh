#!/usr/bin/env bash
# Deploy a verified immutable release through the production Compose profile.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[^/@[:space:]]+(/[^@[:space:]]+)+@sha256:[0-9a-f]{64}$ ]]; then
  printf 'deploy: require fully-qualified image@sha256:<64 lowercase hex>\n' >&2
  exit 2
fi
: "${HERMES_BUNDLE_SHA256:?HERMES_BUNDLE_SHA256 is required}"
: "${HERMES_POLICY_DIR:?HERMES_POLICY_DIR is required}"
: "${COSIGN_BIN:=cosign}"
: "${COMPOSE_FILE:=deploy/compose/production.yaml}"
image_ref="$1"

if [[ -n "${COSIGN_KEY:-}" ]]; then
  "$COSIGN_BIN" verify --key "$COSIGN_KEY" "$image_ref" >/dev/null
elif [[ -n "${COSIGN_IDENTITY:-}" && -n "${COSIGN_ISSUER:-}" ]]; then
  "$COSIGN_BIN" verify "$image_ref" \
    --certificate-identity "$COSIGN_IDENTITY" \
    --certificate-oidc-issuer "$COSIGN_ISSUER" >/dev/null
else
  printf 'deploy: configure COSIGN_KEY or COSIGN_IDENTITY + COSIGN_ISSUER\n' >&2
  exit 2
fi

export HERMES_PROXY_IMAGE="$image_ref"
docker compose -f "$COMPOSE_FILE" config >/dev/null
docker compose -f "$COMPOSE_FILE" up -d --force-recreate hermes-proxy >/dev/null
container_id=$(docker compose -f "$COMPOSE_FILE" ps -q hermes-proxy)
test -n "$container_id"
for _ in $(seq 1 30); do
  digest_match=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$container_id" | grep -Fx "$image_ref" || true)
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$container_id")
  [[ -n "$digest_match" && "$status" == healthy ]] && exit 0
  [[ "$status" == unhealthy ]] && { printf 'deploy: proxy unhealthy\n' >&2; exit 1; }
  sleep 2
done
printf 'deploy: timeout waiting for verified digest and readiness\n' >&2
exit 1
