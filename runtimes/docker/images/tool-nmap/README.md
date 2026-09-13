# hermes-tool-nmap — image tool pihak ketiga (§13.1)

Satu tool = satu image terpisah. Image ini berisi:

- `nmap` **7.93+dfsg1-1** (versi apt **TER-PIN** dari repo Debian
  bookworm main, di-install **saat build** — bukan runtime).
- `/wrapper` — gate fail-closed di depan nmap (ENTRYPOINT, bukan nmap
  langsung): verifikasi SHA-256 policy bundle, scope check target,
  budget (max ports + max rate), whitelist argumen, dan normalisasi output
  greppable ke `validation-result.json` + provenance.

Runtime base = `debian:bookworm-slim` (BUKAN distroless — nmap butuh libc
glibc + data files `/usr/share/nmap`), berjalan sebagai **non-root** (uid
65532), tanpa capability khusus: kompatibel `cap_drop: ALL`.

## PERINGATAN WAJIB: port scanning = aktif, risk HIGH

- **Banyak program bug bounty MELARANG port scanning** — kecuali
  dinyatakan eksplisit. Jalankan image ini HANYA terhadap target in-scope
  EKSPLISIT (host tercantum di `allowed_hosts` bundle, satu host per run).
- **Risk classification: HIGH (§8)** → wajib approval eksplisit sebelum
  eksekusi, budget ketat, dan stop conditions aktif.
- Mode scan **WAJIB `-sT` (connect scan)**: tidak butuh `NET_RAW` /
  `CAP_NET_RAW`, kompatibel `cap_drop: ALL`. Mode raw socket (`-sS`,
  `-sU`, `-sO`, `-sA`) **tidak bisa dipakai** — wrapper tidak punya jalur
  pass-through argumen, argumen posisional ekstra ditolak (exit 2), dan
  argv diverifikasi ulang terhadap whitelist sebelum exec. Escalation ke
  mode NET_RAW = image khusus + approval tambahan, post-MVP (§13.1).

## Kebijakan wrapper

1. **Scope check target.** Wajib SATU host (posisional); wajib cocok
   exact dengan bagian host pada `allowed_hosts` bundle. Bentuk CIDR
   (`10.0.0.0/24`), range (`1-5`), wildcard, multi-host, atau flag
   injection (awalan `-`) ditolak (exit 2). Restriction port-level
   (host:port) tetap tanggung jawab control plane + hermes-proxy (§8/§11);
   wrapper membatasi host + jumlah port + rate.
2. **Budget → max ports.** `--ports` (spec `-p`) WAJIB diisi — wrapper
   tidak pernah menjalankan scan port-default tanpa persetujuan eksplisit.
   Jumlah total port (range di-expand) wajib `<= bundle.max_requests`;
   lebih = exit 2 (§10). Contoh: `max_requests=1000` memperbolehkan
   `-p 1-1000`.
3. **Budget → max rate.** `--max-rate` di-set dari
   `bundle.rate_limit_rps` (bukan dari caller).
4. **Whitelist argumen tertutup.** Wrapper memanggil nmap dengan tepat:
   `-sT`, `-p <spec ter-validasi>`, `--max-rate <dari bundle>`,
   `-oG <file>`, `<target>`. nmap tidak diberi stdin
   (`cmd.Stdin = nil` → `/dev/null`).
5. **Provenance.** Versi nmap ter-pin di Dockerfile (`ARG NMAP_VERSION`,
   diverifikasi ulang saat build via `dpkg-query`) **dan** di
   `wrapper/main.go` (`const toolVersion`) — keduanya wajib diganti
   bersamaan. Hasil "port open" tetap `status: "observed"` — Hermes yang
   menafsirkan (§17).

Catatan deviasi kecil: whitelist direncanakan memuat `--no-stdin`, tetapi
nmap 7.93 tidak memiliki opsi tersebut (diverifikasi saat build: `nmap:
unrecognized option '--no-stdin'`). Tujuan yang sama dicapai dengan
`cmd.Stdin = nil` (nmap membaca `/dev/null`, tidak pernah interaktif).

## Cara rebuild

Build context **wajib root repo** (wrapper di-`COPY` dari path relatif):

```bash
docker build \
  -f runtimes/docker/images/tool-nmap/Dockerfile \
  -t hermes/tool-nmap:dev \
  .
```

Cek versi nmap di repo bookworm:
`docker run --rm debian:bookworm-slim bash -c "apt-get update -qq && apt-cache policy nmap"`.

## Cara menjalankan (via wrapper)

```bash
# bundle.json: {"version":1,"allowed_hosts":["host.docker.internal:8093"],
#               "max_requests":1000,"rate_limit_rps":50}
SHA=$(sha256sum bundle.json | cut -d' ' -f1)
docker run --rm --read-only --cap-drop ALL \
  -v "$PWD/bundle.json:/bundle/bundle.json:ro" \
  -v "$PWD/out:/workspace/output" \
  -e POLICY_BUNDLE_SHA256="$SHA" \
  hermes/tool-nmap:dev \
  --bundle /bundle/bundle.json \
  --input /bundle/validation-task.json \
  --ports 1-1000 \
  host.docker.internal
```

Flag wrapper: `--bundle` (wajib), `--input` (validation-task.json),
`--output` (default `/workspace/output/validation-result.json`),
`--ports`/`-p` (wajib — spec `-p` nmap), `--nmap`, dan **tepat satu** host
sebagai argumen posisional. Tidak ada pass-through argumen lain.

## Output

Per port open pada output greppable → satu observation:

```json
{
  "task_id": "...",
  "validator": {"id": "tool-nmap", "version": "0.1.0"},
  "status": "observed",
  "observations": [{"type": "open_port", "detail": "192.168.65.2:8093"}],
  "evidence_refs": ["/workspace/output/nmap-output.gnmap"],
  "provenance": {"tool": "nmap", "tool_version": "7.93+dfsg1-1"}
}
```

`detail` berbentuk `host:port` (host = IP hasil resolve nmap pada baris
greppable). Port non-open tidak menjadi observation; baris `Status: Up`
juga tidak (status host bukan temuan).

## Fail-closed (exit code)

- `0` — `validation-result.json` ditulis (status `observed` + provenance).
- `1` — kegagalan eksekusi nmap.
- `2` — policy/scope rejection: bundle hilang/hash mismatch, target di
  luar `allowed_hosts`, target CIDR/range/wildcard/multi-host, `--ports`
  kosong / format salah / jumlah port melebihi `max_requests`, task tidak
  valid, atau ada argumen ekstra (percobaan `-sS`/`-sU`/`-sO`/`-sA`
  termasuk di sini). Uji cepat: `--ports 1-1000 -sS host` → exit 2, nmap
  tidak dieksekusi.
