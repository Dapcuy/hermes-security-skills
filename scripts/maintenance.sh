#!/usr/bin/env bash
# Run the approved offline backup and age-based case retention pass.
# Schedule this script from cron/systemd/Task Scheduler with a service account
# that can read state and write only the backup destination.
set -euo pipefail

: "${HERMES_SECURITY_BIN:=hermes-security}"
: "${HERMES_AUDIT_FILE:=audit/audit.jsonl}"
: "${HERMES_JOBS_DIR:=jobs}"
: "${HERMES_EVIDENCE_DIR:=}"
: "${HERMES_STATE_DIR:=}"
: "${HERMES_KNOWLEDGE_DIR:=knowledge}"
: "${HERMES_BACKUP_DIR:=backups}"
: "${HERMES_RETENTION_AGE:=720h}"

lock="${HERMES_MAINTENANCE_LOCK:=.hermes-maintenance.lock}"
if ! mkdir "$lock" 2>/dev/null; then
  printf 'maintenance: another run is active\n' >&2
  exit 2
fi
cleanup() { rmdir "$lock" 2>/dev/null || true; }
trap cleanup EXIT

stamp=$(date -u +%Y%m%dT%H%M%SZ)
archive="$HERMES_BACKUP_DIR/hermes-$stamp.tar.gz"

"$HERMES_SECURITY_BIN" backup create \
  --out "$archive" \
  --audit-file "$HERMES_AUDIT_FILE" \
  --jobs-dir "$HERMES_JOBS_DIR" \
  --evidence-dir "$HERMES_EVIDENCE_DIR" \
  --state-dir "$HERMES_STATE_DIR" \
  --knowledge-dir "$HERMES_KNOWLEDGE_DIR"
"$HERMES_SECURITY_BIN" backup verify --archive "$archive" --audit-file "$HERMES_AUDIT_FILE"

shopt -s nullglob
for case_dir in "$HERMES_JOBS_DIR"/*; do
  [[ -d "$case_dir" ]] || continue
  case_id=$(basename "$case_dir")
  output=''
  if output=$("$HERMES_SECURITY_BIN" case clean "$case_id" \
      --force --min-age "$HERMES_RETENTION_AGE" \
      --jobs-dir "$HERMES_JOBS_DIR" --audit-file "$HERMES_AUDIT_FILE" 2>&1); then
    printf 'maintenance: retention cleanup completed\n'
  elif grep -q 'younger than retention minimum' <<<"$output"; then
    printf 'maintenance: retention skipped young case\n'
  else
    printf '%s\n' "$output" >&2
    exit 1
  fi
done
