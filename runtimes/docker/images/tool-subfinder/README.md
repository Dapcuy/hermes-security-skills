# hermes-tool-subfinder — image tool pihak ketiga (§13.1)

Satu tool = satu image terpisah. Image ini berisi:

- `subfinder` **v2.16.0** (binary Go statis, ter-pin, di-install **saat
  build** — bukan runtime).
- `/wrapper` — gate fail-closed di depan subfinder (ENTRYPOINT, bukan
  subfinder langsung): verifikasi SHA-256 policy bundle, scope check domain,
  budget/deadline, whitelist argumen, dan normalisasi output ke
  `validation-result.json` + provenance.

Runtime base = `gcr.io/distroless/static-debian12:nonroot` — tanpa shell,
tanpa package manager, non-root. Tidak ada jalur install/download apa pun
saat runtime; jalankan container dengan `--read-only` (tmpfs `/tmp`) untuk
baseline penuh.

## CATATAN DESAIN WAJIB: passive recon & third-party data sources

subfinder melakukan **passive subdomain enumeration**: ia TIDAK mengirim
request ke target, melainkan meng-query **third-party data sources publik**
(crt.sh, HackerTarget, DNSDumpster, AlienVault OTX, dll.).

Konsekuensi desain:

1. **Sumber data adalah pihak ketiga, BUKAN target.** Koneksi keluar dari
   container ke crt.sh dkk. adalah perilaku normal passive recon — bukan
   "active scanning" terhadap target, dan tidak memicu klasifikasi risiko
   active scan (§8).
2. **Scope check tetap wajib.** Yang dikontrol wrapper adalah DOMAIN yang
   di-enumerate: `-d <domain>` wajib cocok **exact** dengan host pada
   `allowed_hosts` bundle. Wrapper menolak (exit 2) domain di luar scope,
   wildcard, dan bentuk non-FQDN. Ini memastikan hanya domain in-scope yang
   di-enumerate — bukan membatasi ke mana subfinder bertanya (itu masalah
   egress, dijawab hermes-proxy §11).
3. **Provenance & determinism**: versi subfinder ter-pin di Dockerfile dan
   dicatat wrapper di `provenance.tool_version`. `-duc` (disable update
   check) memastikan runtime tidak pernah mengunduh/meng-update apa pun.
   Hasil antar-run bisa berbeda karena data sources adalah black box yang
   berubah terus — itu trade-off yang diterima §13.1; hasil tetap
   `status: "observed"` dan Hermes yang menafsirkan (§17).

## Cara rebuild

Build context **wajib root repo** (wrapper di-`COPY` dari path relatif):

```bash
docker build \
  -f runtimes/docker/images/tool-subfinder/Dockerfile \
  -t hermes/tool-subfinder:dev \
  .
```

Catatan: versi subfinder (`v2.16.0`) ter-pin di Dockerfile **dan** di
`wrapper/main.go` (`const toolVersion`) — keduanya wajib diganti bersamaan
(satu PR = satu bump versi; cek tag stabil terbaru via
`git ls-remote --tags https://github.com/projectdiscovery/subfinder`).

## Cara menjalankan (via wrapper)

```bash
# bundle.json: {"version":1,"allowed_hosts":["example.com"],
#               "max_requests":500,"rate_limit_rps":10}
SHA=$(sha256sum bundle.json | cut -d' ' -f1)
docker run --rm --read-only --tmpfs /tmp:rw,noexec,size=64m \
  -v "$PWD/bundle.json:/bundle/bundle.json:ro" \
  -v "$PWD/out:/workspace/output" \
  -e POLICY_BUNDLE_SHA256="$SHA" \
  hermes/tool-subfinder:dev \
  --bundle /bundle/bundle.json \
  --input /bundle/validation-task.json \
  -d example.com
```

Flag wrapper: `--bundle` (wajib), `--input` (validation-task.json),
`--output` (default `/workspace/output/validation-result.json`),
`--subfinder`, dan **tepat satu** domain target via `-d <domain>` (semantik
sama dengan `-d` subfinder) atau satu argumen posisional. Tidak ada
pass-through argumen lain — subfinder dijalankan dengan
`-d <domain> -o <file> -silent -duc` (whitelist tertutup).

## Output

Per baris subdomain → satu observation:

```json
{
  "task_id": "...",
  "validator": {"id": "tool-subfinder", "version": "0.1.0"},
  "status": "observed",
  "observations": [{"type": "subdomain", "detail": "api.example.com"}],
  "evidence_refs": ["/workspace/output/subfinder-output.txt"],
  "provenance": {"tool": "subfinder", "tool_version": "v2.16.0"}
}
```

Baris output yang tidak seperti hostname di-skip dengan peringatan (bukan
dipercaya buta). Budget: subfinder passive sehingga `max_requests/rate_limit_rps`
di-map ke **deadline** eksekusi (+grace); lewat deadline, proses di-kill
(stop condition §10).

## Fail-closed (exit code)

- `0` — `validation-result.json` ditulis (status `observed` + provenance).
- `1` — kegagalan eksekusi subfinder.
- `2` — policy/scope rejection: bundle hilang/hash mismatch, domain di luar
  `allowed_hosts` / wildcard / bukan FQDN, task tidak valid, atau jumlah
  argumen salah. (Uji cepat: `-d evil.com` → exit 2, subfinder tidak
  dieksekusi.)
