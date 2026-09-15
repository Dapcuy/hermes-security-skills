# Production deployment and recovery runbook

Dokumen ini adalah prosedur operasional minimum untuk profile production. Jangan
menjalankan profile production dengan image tag mutable atau tanpa policy bundle
terverifikasi.

## Prerequisites

- Docker Engine/Desktop dengan Compose v2.
- Proxy image fully-qualified dan digest-pinned:
  `ghcr.io/<org>/hermes-proxy@sha256:<64 lowercase hex>`.
- Policy bundle read-only dan `HERMES_BUNDLE_SHA256` dihitung dari file yang sama.
- Release bundle artifact yang memuat digest image, SBOM reference, dan Cosign
  identity/issuer.
- Direktori state berikut tersedia dan dapat dibaca oleh operator backup:
  `audit/audit.jsonl`, `jobs/`, `knowledge/`, dan optional state/evidence roots
  yang benar-benar terpisah (root yang overlap ditolak).

## Start and verify

```bash
export HERMES_PROXY_IMAGE='ghcr.io/<org>/hermes-proxy@sha256:<digest>'
export HERMES_POLICY_DIR="$PWD/policy-bundle"
export HERMES_BUNDLE_SHA256='<sha256 of policy-bundle/bundle.json>'
docker compose -f deploy/compose/production.yaml config
docker compose -f deploy/compose/production.yaml up -d
docker compose -f deploy/compose/production.yaml ps
```

The profile publishes no host port. Consumers must reach the proxy through the
internal Compose network. The native container healthcheck calls only the local
`/readyz` endpoint and does not probe an external target.

## Offline backup

Run from the repository/state root. Backup is fail-closed: a missing root,
symlink, traversal path, duplicate archive entry, or invalid audit chain aborts
the operation.

```bash
hermes-security backup create \
  --out backups/hermes-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  --audit-file audit/audit.jsonl \
  --jobs-dir jobs \
  --knowledge-dir knowledge

hermes-security backup verify --archive backups/<archive>.tar.gz --sha256 <trusted-sha256>
```

Store the resulting archive outside the live state roots. The command performs
post-write verification and appends a tamper-evident audit event.

## Restore drill

Always restore into a new, empty destination. The restore implementation stages
all files, validates manifest hashes and every restored `audit.jsonl` chain, and
only then renames the staging directory into place.

```bash
hermes-security backup verify --archive backups/<archive>.tar.gz --sha256 <trusted-sha256>
hermes-security backup restore \
  --archive backups/<archive>.tar.gz \
  --sha256 <trusted-sha256> \
  --dir recovery-drill/<timestamp> \
  --audit-file audit/restore-audit.jsonl
```

Do not point a restore at a live state directory. Existing destinations are
rejected to prevent accidental merge or overwrite.

## Retention

`case clean` is dry-run by default and requires `--force`. The default minimum
case age is 24 hours. The `--min-age 0s` override is intended only for an
explicitly approved test or incident procedure and should be recorded in the
operator audit trail.

```bash
hermes-security case clean <case-id> --jobs-dir jobs
hermes-security case clean <case-id> --force --jobs-dir jobs
```

Unknown top-level entries and symlinks are rejected before cleanup. Audit and
approval stores outside the case workspace are never deleted by this command.

## Rollback

Select the previous verified digest from `release-bundle.json`, update
`HERMES_PROXY_IMAGE`, re-run `docker compose ... config`, and recreate the
service. Never rollback by moving a mutable tag. Verify `/readyz` and the
release digest after the rollback.
