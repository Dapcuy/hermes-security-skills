# hermes-tool-httpx — image tool pihak ketiga (§13.1)

Satu tool = satu image terpisah. Image ini berisi:

- `httpx` **v1.12.0** (binary Go statis, ter-pin, di-install **saat build**
  — bukan runtime).
- `/wrapper` — gate fail-closed di depan httpx (ENTRYPOINT, bukan httpx
  langsung): verifikasi SHA-256 policy bundle, scope check SETIAP URL
  target, budget/rate limit, whitelist argumen, dan normalisasi output ke
  `validation-result.json` + provenance.

Runtime base = `gcr.io/distroless/static-debian12:nonroot` — tanpa shell,
tanpa package manager, non-root. Tidak ada jalur install/download apa pun
saat runtime; jalankan container dengan `--read-only` (tmpfs `/tmp`) untuk
baseline penuh.

## Kebijakan wrapper

1. **Scope check SETIAP URL.** Target boleh berupa URL posisional (satu
   atau lebih) dan/atau `--list <file>` (satu URL per baris). SEMUA host
   wajib cocok `allowed_hosts` bundle: entry `host:port` cocok exact, entry
   `host` (tanpa port) hanya untuk port default 80/443. **Satu saja URL di
   luar scope = REJECT seluruh run (exit 2)** — fail-closed, bukan "jalan
   separuh". Scope matching wrapper sengaja simple (exact match); matcher
   lengkap (DNS, private IP, redirect) adalah tanggung jawab control plane
   + hermes-proxy (§8, §11).
2. **Budget → rate limit + deadline.** `rate_limit_rps` bundle diteruskan
   ke httpx via `-rate-limit`; `max_requests/rate_limit_rps` (+grace)
   menjadi deadline eksekusi — lewat deadline httpx di-kill (stop
   condition §10). Budget presisi per-request tetap di hermes-proxy (§11).
3. **Whitelist argumen tertutup.** Wrapper memanggil httpx dengan:
   `-l/-u`, `-o`, `-status-code`, `-title`, `-tech-detect`, `-json`,
   `-rate-limit <dari bundle>`, `-duc` (disable update check — runtime
   tidak pernah mengunduh/meng-update apa pun, sejalan dengan §13.1).
   Tidak ada pass-through argumen mentah, tidak ada shell.
4. **Provenance.** Versi httpx ter-pin di Dockerfile **dan** di
   `wrapper/main.go` (`const toolVersion`) — keduanya wajib diganti
   bersamaan (satu PR = satu bump versi). Hasil "exposed/failed" dari httpx
   tetap `status: "observed"` — Hermes yang menafsirkan (§17).

## Cara rebuild

Build context **wajib root repo** (wrapper di-`COPY` dari path relatif):

```bash
docker build \
  -f runtimes/docker/images/tool-httpx/Dockerfile \
  -t hermes/tool-httpx:dev \
  .
```

Cek tag stabil terbaru via
`git ls-remote --tags https://github.com/projectdiscovery/httpx`.

## Cara menjalankan (via wrapper)

```bash
# bundle.json: {"version":1,"allowed_hosts":["host.docker.internal:8093"],
#               "max_requests":100,"rate_limit_rps":20}
SHA=$(sha256sum bundle.json | cut -d' ' -f1)
docker run --rm --read-only --tmpfs /tmp:rw,noexec,size=64m \
  -v "$PWD/bundle.json:/bundle/bundle.json:ro" \
  -v "$PWD/out:/workspace/output" \
  -e POLICY_BUNDLE_SHA256="$SHA" \
  hermes/tool-httpx:dev \
  --bundle /bundle/bundle.json \
  --input /bundle/validation-task.json \
  -u http://host.docker.internal:8093/
```

Banyak target: `-u` boleh diulang atau dipisah koma (semantik httpx), atau
`-l /bundle/urls.txt` (file satu URL per baris, mount read-only), atau
beberapa URL posisional. Semua sumber target digabung dan di-scope check.
Wrapper menulis file target sementara di `/tmp` dan memanggil httpx dengan
`-l` bila target > 1.

## Output

Per URL hasil probe → satu observation:

```json
{
  "task_id": "...",
  "validator": {"id": "tool-httpx", "version": "0.1.0"},
  "status": "observed",
  "observations": [
    {"type": "probe", "detail": "http://host.docker.internal:8093/ [200] [Directory listing for /] [Python]"}
  ],
  "evidence_refs": ["/workspace/output/httpx-output.json"],
  "provenance": {"tool": "httpx", "tool_version": "v1.12.0"}
}
```

Format detail: `<url> [<status>] [<title>] [<tech>]` — bagian `[<title>]` /
`[<tech>]` dihilangkan bila kosong.

## Fail-closed (exit code)

- `0` — `validation-result.json` ditulis (status `observed` + provenance).
- `1` — kegagalan eksekusi httpx.
- `2` — policy/scope rejection: bundle hilang/hash mismatch, **satu saja**
  URL di luar `allowed_hosts`, scheme bukan http/https, tidak ada target,
  task tidak valid. (Uji cepat: `-u http://example.com/` → exit 2, httpx
  tidak dieksekusi.)
