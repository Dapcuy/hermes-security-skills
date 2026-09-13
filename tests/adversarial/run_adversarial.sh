#!/usr/bin/env bash
# Runner adversarial suite (Windows Git Bash / Linux).
# Pemakaian: bash tests/adversarial/run_adversarial.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

# Toolchain Go lokal (sesuai konvensi environment project).
export PATH="${TEMP:-/tmp}/go/bin:$PATH"
export GOCACHE="${TEMP:-/tmp}/gocache"
export GOPATH="${TEMP:-/tmp}/gopath"

echo "== go build ./... =="
go build ./...

echo "== adversarial unit-level (approval/memory/events/mcp) =="
go test -count=1 -v \
  -run 'TestStore|TestCrafted|TestUntrustedReIngest|TestDuplicateIDAcrossCases|TestIngestFromTarget|TestMarkStalePerCase|TestInspectAndCompare|TestListFailsClosed|TestCacheFingerprint|TestToolsCall|TestFuzzParams|TestServeFuzz|TestServeOversized|TestInspectRequestTraversal' \
  ./internal/approval/ ./internal/memory/ ./internal/events/ ./internal/mcp/

echo "== E2E kill switch (tests/adversarial) =="
go test -count=1 -v ./tests/adversarial/
