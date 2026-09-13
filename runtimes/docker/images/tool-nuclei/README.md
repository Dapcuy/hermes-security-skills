# hermes-tool-nuclei — image tool pihak ketiga (§13.1)

Satu tool = satu image terpisah. Image ini berisi:

- `nuclei` **v3.3.9** (ter-pin, di-install **saat build** — bukan runtime).
- **Nuclei templates ter-bake** di `/nuclei-templates` pada tag terpin
  (`ARG NUCLEI_TEMPLATES_TAG`, saat ini `v10.4.8`) + file
  `/nuclei-templates/.hermes-templates-version` yang dicatat wrapper ke
  provenance evidence.
- `/wrapper` — gate fail-closed di depan nuclei (ENTRYPOINT, bukan nuclei
  langsung): verifikasi SHA-256 policy bundle, scope check, budget/rate
  limit, whitelist argumen, `-duc` (disable update check), dan normalisasi
  output ke `validation-result.json` + provenance.

Runtime base = `gcr.io/distroless/static-debian12:nonroot` — tanpa shell,
tanpa package manager, non-root. Tidak ada jalur install/download apa pun
saat runtime; jalankan container dengan `--read-only` (tmpfs `/tmp`) untuk
baseline penuh.

## Mengapa template di-bake, bukan di-download (§13.1)

Nuclei templates adalah **supply chain vector** — template community pernah
menjadi jalur serangan. Karena itu:

1. Template di-clone **saat build** pada **tag rilis terpin** (bukan HEAD
   yang bergerak), di-review, lalu di-bake ke image.
2. Runtime **tidak pernah** mengunduh/meng-update template: wrapper memakai
   `-duc`, runtime read-only + nonroot, dan wrapper **menolak jalan
   (exit 2)** bila `/nuclei-templates` tidak ada atau tidak memuat satu
   `.yaml` pun.
3. Versi tool + versi template dicatat di `provenance` pada
   `validation-result.json` (syarat §13.1/§8 — output tool tanpa provenance
   adalah finding ilegal).

## Cara rebuild

Build context **wajib root repo** (wrapper di-`COPY` dari path relatif):

```bash
docker build \
  -f runtimes/docker/images/tool-nuclei/Dockerfile \
  -t hermes/tool-nuclei:dev \
  .
```

Opsional: override tag template saat eksperimen (jangan untuk rilis tanpa
review): `--build-arg NUCLEI_TEMPLATES_TAG=vX.Y.Z`.

## Cara update versi template (prosedur review supply chain §13.1)

1. Cek tag rilis stabil terkini:
   `git ls-remote --tags https://github.com/projectdiscovery/nuclei-templates`.
2. Ubah default `ARG NUCLEI_TEMPLATES_TAG` di `Dockerfile`.
3. **Review diff template antar versi** (clone kedua tag, bandingkan):
   periksa template baru yang mencurigakan (payload eksternal, interaksi
   jaringan aneh, `code:` template yang mengeksekusi sesuatu).
4. Rebuild image, jalankan ulang verifikasi wrapper (scan lokal + negative
   test `--templates` seperti di bawah).
5. Satu PR = satu bump versi, sebutkan tag lama → baru di deskripsi PR.

Catatan: versi nuclei (`v3.3.9`) ter-pin di Dockerfile **dan** di
`wrapper/main.go` (`const toolVersion`) — keduanya wajib diganti bersamaan.

## Cara menjalankan (via wrapper)

```bash
# bundle.json: {"version":1,"allowed_hosts":["host.docker.internal:PORT"],
#               "max_requests":10,"rate_limit_rps":2}
SHA=$(sha256sum bundle.json | cut -d' ' -f1)
docker run --rm --read-only --tmpfs /tmp:rw,noexec,size=64m \
  -v "$PWD/bundle.json:/bundle/bundle.json:ro" \
  -v "$PWD/out:/workspace/output" \
  -e POLICY_BUNDLE_SHA256="$SHA" \
  hermes/tool-nuclei:dev \
  --bundle /bundle/bundle.json \
  --input /bundle/validation-task.json \
  --templates /nuclei-templates \
  -target http://host.docker.internal:PORT/
```

Flag wrapper: `--bundle` (wajib), `--input` (validation-task.json),
`--output` (default `/workspace/output/validation-result.json`),
`--templates` (default `/nuclei-templates`; boleh direktori sub-set atau
satu file `.yaml` — sesuai budget scan), `--nuclei`, dan **tepat satu**
target sebagai argumen posisional. Tidak ada pass-through argumen lain.

## Fail-closed (exit code)

- `0` — `validation-result.json` ditulis (status `observed` + provenance).
- `1` — kegagalan eksekusi nuclei.
- `2` — policy/asset rejection: bundle hilang/hash mismatch, target di luar
  `allowed_hosts`, task tidak valid, atau **direktori template tidak
  ada/kosong** (uji cepat:
  `--templates /tidak-ada` → exit 2, nuclei tidak dieksekusi).
