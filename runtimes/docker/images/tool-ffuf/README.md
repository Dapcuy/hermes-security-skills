# hermes-tool-ffuf — image tool pihak ketiga (§13.1)

Satu tool = satu image terpisah. Image ini berisi:

- `ffuf` **v2.3.0** (binary Go statis, ter-pin, di-install **saat build**
  — bukan runtime).
- **Wordlists ter-bake** di `/wordlists` — subset KECIL terkurasi dari
  SecLists pada tag terpin (`ARG SECLISTS_TAG`, saat ini `2026.1`):
  `common.txt` dan `raft-small-words.txt` (Discovery/Web-Content), plus
  file `/wordlists/.hermes-wordlists-version` yang dicatat wrapper ke
  provenance evidence. Bukan seluruh repo SecLists — jaga ukuran image.
- `/wrapper` — gate fail-closed di depan ffuf (ENTRYPOINT, bukan ffuf
  langsung): verifikasi SHA-256 policy bundle, scope check target URL,
  wordlist ter-bake wajib, budget/rate limit, whitelist argumen, dan
  normalisasi output ke `validation-result.json` + provenance.

Runtime base = `gcr.io/distroless/static-debian12:nonroot` — tanpa shell,
tanpa package manager, non-root. Tidak ada jalur install/download apa pun
saat runtime; jalankan container dengan `--read-only` (tmpfs `/tmp`) untuk
baseline penuh.

## Mengapa wordlist di-bake, bukan di-download (§13.1)

Wordlist/template adalah **aset yang di-bake saat build**, bukan aset
runtime — pola sama dengan nuclei templates (§13.1):

1. SecLists di-clone **saat build** pada **tag rilis terpin** (bukan HEAD
   yang bergerak), subset terkurasi di-review, lalu di-bake ke image.
2. Runtime **tidak pernah** mengunduh wordlist: wrapper **menolak jalan
   (exit 2)** bila `--wordlist` tidak diberikan, file tidak ada, atau
   kosong — mirip pola `--templates` tool-nuclei.
3. Versi tool + versi wordlist dicatat di `provenance` pada
   `validation-result.json` (`tool_version` = v2.3.0,
   `wordlists_version` = tag SecLists; syarat §13.1/§8 — output tool tanpa
   provenance adalah finding ilegal).

Ubah `SECLISTS_TAG` = review supply chain (§13.1): cek tag terbaru via
`git ls-remote --tags https://github.com/danielmiessler/SecLists`, review
isi subset yang di-bake, rebuild, ulangi verifikasi wrapper.

## Kebijakan wrapper

1. **Scope check target URL** — `-u` wajib cocok `allowed_hosts` bundle
   (entry `host:port` exact; entry `host` hanya port default 80/443).
   Fail-closed exit 2.
2. **`--wordlist` WAJIB** — fail-closed exit 2 kalau kosong / file tidak
   ada / berukuran 0 (pola `--templates` tool-nuclei).
3. **Budget → rate limit + deadline** — `-rate` diambil dari
   `bundle.rate_limit_rps` (bukan caller); deadline =
   `max_requests/rate_limit_rps` + grace, lewat deadline ffuf di-kill
   (§10). Catatan: output file ffuf ditulis di akhir run — kill karena
   budget bisa berarti tidak ada evidence mentah (sama dengan tool-nuclei).
4. **Whitelist argumen tertutup** — wrapper memanggil ffuf dengan tepat:
   `-w`, `-u`, `-o`, `-of json`, `-mc`, `-fc` (opsional), `-t` (maks 10,
   fail-closed jika lebih), `-rate`. Tidak ada pass-through, tidak ada
   shell. `-mc` default wrapper: `200,204,301,302,307,308,401,403`
   (eksplisit agar deterministik antar versi ffuf).
5. **Provenance** — versi ffuf ter-pin di Dockerfile **dan** di
   `wrapper/main.go` (`const toolVersion`) — keduanya wajib diganti
   bersamaan. "Fuzz hit" tetap `status: "observed"` — Hermes yang
   menafsirkan (§17).

## Cara rebuild

Build context **wajib root repo** (wrapper di-`COPY` dari path relatif):

```bash
docker build \
  -f runtimes/docker/images/tool-ffuf/Dockerfile \
  -t hermes/tool-ffuf:dev \
  .
```

Catatan: tag SecLists 2026.1 tidak lagi memuat `Discovery/Web-Content/small.txt`
— padanannya yang di-bake adalah `raft-small-words.txt` (+ `common.txt`).

## Cara menjalankan (via wrapper)

```bash
# bundle.json: {"version":1,"allowed_hosts":["host.docker.internal:8093"],
#               "max_requests":2000,"rate_limit_rps":50}
SHA=$(sha256sum bundle.json | cut -d' ' -f1)
docker run --rm --read-only --tmpfs /tmp:rw,noexec,size=64m \
  -v "$PWD/bundle.json:/bundle/bundle.json:ro" \
  -v "$PWD/out:/workspace/output" \
  -e POLICY_BUNDLE_SHA256="$SHA" \
  hermes/tool-ffuf:dev \
  --bundle /bundle/bundle.json \
  --input /bundle/validation-task.json \
  --wordlist /wordlists/common.txt \
  -u http://host.docker.internal:8093/FUZZ
```

Flag wrapper: `--bundle` (wajib), `--input` (validation-task.json),
`--output` (default `/workspace/output/validation-result.json`),
`--wordlist`/`-w` (wajib — pilih dari `/wordlists` ter-bake; semantik
`-w` ffuf: boleh diulang/dipisah koma, dukung `:KEYWORD`), `--mc` (opsional),
`--fc` (opsional), `--t` (opsional, maks 10), `--ffuf`, dan **tepat satu**
URL target via `-u <url>` (semantik `-u` ffuf, memuat kata kunci `FUZZ`)
atau satu argumen posisional. Tidak ada pass-through argumen lain —
`-o`, `-of`, `-rate` selalu di-set wrapper sendiri.

## Output

Per entri hasil ffuf → satu observation:

```json
{
  "task_id": "...",
  "validator": {"id": "tool-ffuf", "version": "0.1.0"},
  "status": "observed",
  "observations": [
    {"type": "fuzz_hit", "detail": "http://host.docker.internal:8093/index.html [200] [13]"}
  ],
  "evidence_refs": ["/workspace/output/ffuf-output.json"],
  "provenance": {"tool": "ffuf", "tool_version": "v2.3.0", "wordlists_version": "2026.1"}
}
```

Format detail: `<url> [status] [size]` (size = panjang response dalam byte).

## Fail-closed (exit code)

- `0` — `validation-result.json` ditulis (status `observed` + provenance).
- `1` — kegagalan eksekusi ffuf.
- `2` — policy/asset rejection: bundle hilang/hash mismatch, target URL di
  luar `allowed_hosts`, `--wordlist` **kosong / file tidak ada / file
  kosong** (uji cepat: jalankan tanpa `--wordlist` → exit 2, ffuf tidak
  dieksekusi), `-mc`/`-fc` format salah, `-t` > 10, task tidak valid, atau
  jumlah argumen salah.
