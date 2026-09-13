# hermes-proxy

Interception proxy self-hosted (ROADMAP §11, §38 — Phase 7): **satu-satunya
komponen dengan privilege egress**. Policy in-line — setiap request dievaluasi
SAAT eksekusi (TOCTOU guard), fail-closed terhadap policy bundle.

Stdlib only (`net/http`, `crypto/tls`, `crypto/x509`, `crypto/sha256`).
Logika engine ada di `internal/proxycore` (dipakai bersama Mode 1 dan Mode 2).

## Build

```bash
go build ./cmd/hermes-proxy
```

## Mode 1 — Replay engine (MVP)

```bash
BUNDLE=runtimes/proxy/policy-bundle/example-bundle.json
SHA=$(sha256sum "$BUNDLE" | cut -d' ' -f1)

hermes-proxy \
  --bundle "$BUNDLE" \
  --bundle-sha256 "$SHA" \
  --addr 127.0.0.1:8080 \
  --evidence-dir ./jobs/evidence
```

### Flag

| Flag | Default | Keterangan |
|---|---|---|
| `--bundle` | (wajib) | Path policy bundle JSON. Tanpa bundle = proxy menolak semua (fail-closed). |
| `--bundle-sha256` | (wajib) | SHA-256 hex bundle. Mismatch = tidak start. |
| `--addr` | `127.0.0.1:8080` | Alamat listen control channel. |
| `--bind` | `loopback` | `all` = listen `0.0.0.0` — **HANYA** untuk mode container di Docker network internal (§11). Jangan publish port ke host. |
| `--evidence-dir` | `./jobs/evidence` | Direktori evidence file (§25). |
| `--max-body-bytes` | `0` (otomatis) | Context budget inline body; 0 = pakai `max_body_bytes` bundle atau 8192. Nilai flag hanya boleh memperketat, tidak boleh melampaui bundle. |
| `--mitm` | `false` | Aktifkan Mode 2 (eksperimental). |
| `--mitm-addr` | `127.0.0.1:8081` | Alamat listen CONNECT MITM. |
| `--ca-out` | (kosong) | Ekspor sertifikat publik CA MITM ke file PEM (private key **tidak** pernah ditulis ke disk). |

### Contract API — `POST /execute`

Request:

```json
{"url": "http://localhost:8000/", "method": "GET",
 "headers": {"Accept": "text/plain"}, "body": "opsional, untuk POST/PUT/PATCH"}
```

Respons sukses:

```json
{
  "status": "executed",
  "response": {"status": 200, "headers": {...}, "body": "...", "truncated": false},
  "evidence_ref": "evidence-000001.json",
  "evidence_sha256": "…",
  "latency_ms": 12,
  "redirect": {"followed": false, "blocked": false, "location": "", "hops": 0}
}
```

Respons gagal (fail-closed):

```json
{"status": "denied", "reason": "scope: host di luar scope"}
```

Kode status: `200` executed · `400` input tidak valid · `403` scope/policy ·
`429` budget habis / rate limit · `405` bukan POST · `502` kegagalan transport
ke target (`{"status":"error","error":...}`).

### Jalur policy per request (in-line, §11)

1. **Scope check** via `internal/scope` terhadap `allowed_hosts` — per hop,
   termasuk saat eksekusi (bukan hanya saat planning).
2. **Rate limit** token bucket dari `rate_limit_rps` (burst = rps); melebihi =
   429, tidak pernah menunggu.
3. **Budget** `max_requests` global (counter mutex); habis = 429.
4. **Redirect**: default NO-FOLLOW (hanya tercatat di `redirect.location`).
   Bila bundle `follow_redirects: true`, tiap hop di-re-validate terhadap
   scope; redirect out-of-scope = berhenti + `redirect.blocked: true` +
   tercatat di evidence. Maksimal 10 hop.
5. **Redaksi** (§24/§25): header `Authorization`, `Cookie`, `Set-Cookie`,
   `X-Api-Key`, dan header yang mengandung `token`/`key`/`secret` diganti
   `"[REDACTED]"` sebelum keluar dari proxy (respons API dan evidence).
6. **Context budget**: body di-truncate ke `max_body_bytes` dengan
   `truncated: true`; body penuh hanya masuk evidence file (base64).
7. **Evidence** (§25): tiap eksekusi menulis `evidence-<seq>.json` berisi
   request/response penuh (header diredaksi) + `sha256` + `captured_at` +
   `provenance {component: hermes-proxy}`.

Header hop-by-hop (`Host`, `Connection`, `Transfer-Encoding`, dst.) tidak
dibawa dari instruksi replay ke request outbound.

## Mode 2 — TLS MITM (EKSPERIMENTAL)

```bash
hermes-proxy --bundle "$BUNDLE" --bundle-sha256 "$SHA" \
  --mitm --mitm-addr 127.0.0.1:8081 --ca-out ca.pem
```

- CA per-engagement di-generate **in-memory** (ECDSA P-256, validitas 24 jam);
  private key tidak pernah persist (§23). `--ca-out` hanya mengekspor
  sertifikat publik.
- Menangani `CONNECT`: hijack koneksi, balas `200 Connection Established`,
  lalu `tls.Server` dengan leaf certificate dinamis **per SNI** yang
  ditandatangani CA ephemeral.
- Request hasil intercept melewati **jalur policy yang sama** dengan Mode 1
  (scope, budget, rate limit, redaksi) dan tercatat sebagai evidence.
- Client uji memasang CA tersebut sebagai root (custom `RootCAs`), bukan
  browser. Untuk target TLS lokal, gunakan hostname (`localhost:port`) di
  `allowed_hosts` — literal IP loopback selalu ditolak oleh scope.
- **PERINGATAN**: mode ini eksperimental. Intersepsi hanya sah untuk target
  yang diizinkan policy bundle. Stream antara client dan target diteruskan
  utuh; redaksi hanya berlaku pada evidence (capture), bukan pada passthrough.

## Contoh uji lokal (Mode 1)

```bash
# terminal 1: target lokal
python -m http.server 8000 --bind 127.0.0.1

# terminal 2: proxy
hermes-proxy --bundle "$BUNDLE" --bundle-sha256 "$SHA" --addr 127.0.0.1:8080

# terminal 3: eksekusi
curl -s -X POST http://127.0.0.1:8080/execute \
  -d '{"url":"http://localhost:8000/","method":"GET"}'
```

`localhost:8000` ada di `allowed_hosts` example bundle; literal IP
`127.0.0.1` ditolak oleh scope matcher (fail-closed, anti-SSRF).

## Catatan desain

- Bundle diverifikasi SHA-256 saat start; bundle tamper = semua operasi ditolak.
- `--bind all` mencetak peringatan eksplisit — control channel adalah control
  plane channel (§11), bukan port publik.
- Kegagalan menulis evidence memblokir hasil eksekusi (fail-closed): konten
  target tidak boleh masuk reasoning tanpa evidence (§25).
