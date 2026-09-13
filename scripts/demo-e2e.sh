#!/usr/bin/env bash
# =============================================================================
# demo-e2e.sh — demo happy-path end-to-end hermes-proxy (Mode 1, replay).
#
# Urutan:
#   1. build binary hermes-proxy dari source
#   2. start target lokal (python http.server) + proxy (bundle contoh yang
#      di-generate + verifikasi sha256)
#   3. satu POST /execute
#   4. tampilkan response + evidence
#   5. shutdown + cleanup (direktori kerja sementara dihapus)
#
# Pemakaian:
#   bash scripts/demo-e2e.sh
#
# Variabel lingkungan (opsional):
#   DEMO_TARGET_PORT (default 18900) — port target lokal
#   DEMO_PROXY_PORT  (default 18901) — port control channel proxy
#
# Prasyarat: Go 1.22+, Python 3, curl (semua dalam PATH).
# Script ini HANYA menyentuh localhost — tidak ada traffic keluar.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_PORT="${DEMO_TARGET_PORT:-18900}"
PROXY_PORT="${DEMO_PROXY_PORT:-18901}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/hermes-demo-e2e.XXXXXX")"
PROXY_PID=""
TARGET_PID=""

cleanup() {
	# Matikan proses latar dulu (urutan apapun aman), lalu hapus workdir.
	[ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
	[ -n "$TARGET_PID" ] && kill "$TARGET_PID" 2>/dev/null || true
	wait 2>/dev/null || true
	# Beri jeda kecil agar file binary/exe tidak lagi terkunci (Windows).
	sleep 0.5
	rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> [1/5] Build hermes-proxy dari source"
( cd "$REPO_ROOT" && go build -o "$WORK/hermes-proxy" ./cmd/hermes-proxy )
echo "    binary: $WORK/hermes-proxy"

echo "==> [2/5] Generate policy bundle contoh + start target & proxy"
mkdir -p "$WORK/www" "$WORK/evidence"
cat > "$WORK/www/index.html" <<'HTML'
<!DOCTYPE html>
<html><head><title>hermes demo target</title></head>
<body><h1>HERMES-DEMO-E2E-TARGET-OK</h1></body></html>
HTML
cat > "$WORK/bundle.json" <<JSON
{
  "version": 1,
  "allowed_hosts": ["localhost:${TARGET_PORT}"],
  "max_requests": 10,
  "rate_limit_rps": 5,
  "follow_redirects": false,
  "timeout_seconds": 10,
  "max_body_bytes": 8192
}
JSON
BUNDLE_SHA="$(sha256sum "$WORK/bundle.json" | cut -d' ' -f1)"
echo "    bundle: $WORK/bundle.json (sha256 ${BUNDLE_SHA:0:16}...)"

python -m http.server "$TARGET_PORT" --bind 127.0.0.1 --directory "$WORK/www" &
TARGET_PID=$!
"$WORK/hermes-proxy" \
	--bundle "$WORK/bundle.json" \
	--bundle-sha256 "$BUNDLE_SHA" \
	--addr "127.0.0.1:${PROXY_PORT}" \
	--evidence-dir "$WORK/evidence" &
PROXY_PID=$!

# Tunggu kedua port siap (maks 15 detik) — tidak pakai sleep tetap.
wait_port() {
	local port="$1" name="$2" i
	for i in $(seq 1 150); do
		if (echo > "/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
			echo "    $name siap di 127.0.0.1:${port}"
			return 0
		fi
		sleep 0.1
	done
	echo "    $name TIDAK siap di 127.0.0.1:${port}" >&2
	return 1
}
wait_port "$TARGET_PORT" "target"
wait_port "$PROXY_PORT" "proxy"

echo "==> [3/5] POST /execute (satu eksekusi replay)"
RESPONSE="$(curl -s --max-time 20 -X POST "http://127.0.0.1:${PROXY_PORT}/execute" \
	-d "{\"url\":\"http://localhost:${TARGET_PORT}/\",\"method\":\"GET\"}")"

echo "==> [4/5] Response + evidence"
echo "$RESPONSE" | sed 's/^/    /'
if ! echo "$RESPONSE" | grep -q '"status":"executed"'; then
	echo "    GAGAL: response tidak berstatus executed" >&2
	exit 1
fi
if ! echo "$RESPONSE" | grep -q 'HERMES-DEMO-E2E-TARGET-OK'; then
	echo "    GAGAL: body target tidak terlihat di response" >&2
	exit 1
fi
EVIDENCE="$WORK/evidence/evidence-000001.json"
if [ ! -f "$EVIDENCE" ]; then
	echo "    GAGAL: evidence tidak ada di $EVIDENCE" >&2
	exit 1
fi
echo "    evidence: $EVIDENCE"
python -c "
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
print('    evidence sha256 :', d.get('sha256', '')[:16] + '...')
print('    evidence url    :', d['request']['url'])
print('    evidence status :', d['response']['status'])
print('    provenance      :', d.get('provenance'))
" "$EVIDENCE"

echo "==> [5/5] Shutdown + cleanup (workdir dihapus oleh trap EXIT)"
echo "Demo selesai — semua langkah happy-path lulus."
