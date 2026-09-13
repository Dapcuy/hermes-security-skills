# skill-linter

Validator format skill untuk Hermes Security Skills (ROADMAP.md §7, §7.1).
Alat ini membaca file `SKILL.md` (atau file `.md` lain) dan memeriksa
kepatuhan terhadap format standar skill.

Implementasi Python 3 **stdlib only** (`argparse`, `pathlib`, `re`, `sys`) —
frontmatter (subset YAML `key: value`) di-parse manual, **tanpa PyYAML**.

## Pemakaian

```bash
# Satu file
python tools/skill-linter/lint.py skills/core/evidence-handling/SKILL.md

# Direktori (discan rekursif untuk *.md) — dipakai juga oleh `make lint-skills` dan CI
python tools/skill-linter/lint.py skills/

# Beberapa target sekaligus
python tools/skill-linter/lint.py skills/ tests/fixtures/valid
```

Exit code:

| Kode | Arti |
|---|---|
| `0` | Semua file lolos |
| `1` | Ada pelanggaran aturan pada satu atau lebih file |
| `2` | Error pemakaian: path tidak ditemukan, atau tidak ada file `.md` pada target |

## Aturan

| ID | Aturan | Fatal |
|---|---|---|
| `frontmatter` | Skema frontmatter (lihat detail di bawah) | ya |
| `missing-section` | Section H2 wajib tidak ada | ya |
| `credential-literal` | Ada credential literal di dalam skill | ya |
| `hardcoded-tool` | Ada instruksi hardcode tool eksternal | ya |
| `unknown-capability` | Capability yang dirujuk tidak ada di allowlist | ya |
| `routing-reference` | Konsistensi ROUTING.md <-> skills/**/SKILL.md (aktif saat linting direktori `skills/`) | ya |
| `naming-hint` | `name` frontmatter beda dengan nama direktori | tidak (WARN) |
| `io` | File gagal dibaca (permission, encoding) | ya |

### 1. `frontmatter` — skema frontmatter

Frontmatter wajib berada di antara `---` pertama dan `---` kedua di awal file,
dengan format `key: value` (subset YAML; komentar full-line, komentar inline
` # ...`, scalar quoted sederhana, dan folded/literal scalar `>` / `|`
didukung).

- `name` — wajib, lowercase-kebab: `^[a-z0-9]+(-[a-z0-9]+)*$` (mis. `idor-and-bola`).
- `version` — wajib, semver: `X.Y.Z` dengan prerelease/build opsional (mis. `0.1.0`, `1.0.0-rc.1`).
- `description` — wajib, tidak boleh kosong; mendukung bentuk folded `description: >`.
- `risk` — wajib, salah satu dari `low | medium | high | critical`.
- `requires_credentials` — opsional; bila `true`, section `Required Credentials` wajib ada (lihat aturan 2).

### 2. `missing-section` — section H2 wajib

Semua heading berikut harus ada sebagai H2 (`## Judul`) persis, sesuai §7:

```
Purpose, When To Use, When Not To Use, Authorization Preconditions,
Required Context, Required Capabilities, Core Concepts, Reasoning Workflow,
Allowed Operations, Approval Requirements, Forbidden Operations,
Evidence Requirements, False Positive Checks, Severity Guidance,
Stop Conditions, Output Format, Related Skills
```

Section `Required Credentials` wajib ada **hanya** bila frontmatter
menyatakan `requires_credentials: true`.

Pemeriksaan heading bersifat *fence-aware*: baris `## ...` di dalam code fence
tidak dihitung sebagai section.

### 3. `credential-literal` — tidak ada credential literal

Nilai yang tampak seperti kredensial sungguhan dilarang di mana pun di dalam
file (termasuk di dalam code fence), sesuai prinsip ROADMAP §23
(*credential reference, bukan nilai*).

Pola yang dideteksi — key `token`, `secret`, `password`, `api_key`, `apikey`,
atau `api-key` (case-insensitive), diikuti `:` atau `=`:

- **bentuk quoted**: `api_key = "sk-live-9f8e7d6c5b4a3210"` (nilai tanpa spasi, panjang > 8);
- **bentuk assignment tanpa kutip**: `password=supersecretvalue123`.

Nilai dikecualikan (dianggap placeholder) bila:

- dibungkus `<...>` (mis. `<CONTOH>`);
- seluruhnya huruf besar/angka/underscore (konvensi `EXAMPLE_VALUE`);
- mengandung salah satu substring: `example`, `contoh`, `placeholder`,
  `changeme`, `dummy`, `your-`, `sample` (mis. `example-value`).

Pesan linter tidak pernah menampilkan nilai yang dideteksi — hanya key dan
nomor baris.

### 4. `hardcoded-tool` — tidak ada instruksi hardcode tool

Regex `\bgunakan (curl|nmap|nuclei|sqlmap|burp|caido)\b` (case-insensitive).
Skill harus meminta **capability**, bukan menentukan tool — provider ditentukan
capability registry (ROADMAP §4.1).

### 5. `unknown-capability` — capability harus terdaftar

Semua identifier snake_case (mis. `request_replay`) di dalam body section
`Required Capabilities` harus ada di allowlist berikut (hardcode, disamakan
dengan `capabilities/registry.yaml`; bila registry berubah, sinkronkan
`ALLOWED_CAPABILITIES` di `lint.py`):

```
inspect_request, request_replay, response_comparison,
list_history, json_diff, openapi_analysis,
subfinder_enum, httpx_probe, nmap_scan, ffuf_fuzz
```

Empat entri terakhir adalah capability tool pihak ketiga (ROADMAP §13.1):
satu tool = satu image terkurasi (`hermes-tool-*`), dieksekusi lewat
provider docker dengan wrapper yang menegakkan policy bundle, budget, dan
rate limit. Menyebut identifier capability ini di section `Required
Capabilities` diizinkan; instruksi "gunakan <tool>" tetap dilarang oleh
aturan `hardcoded-tool`.

### 6. `naming-hint` — konsistensi nama (peringatan)

Bila file bernama `SKILL.md` berada di direktori yang namanya juga
lowercase-kebab, nama direktori diharapkan sama dengan `name` frontmatter.
Pelanggaran dicetak sebagai `WARN` dan **tidak** memengaruhi exit code.

### 7. `routing-reference` — konsistensi ROUTING.md <-> skills/

Rule ini **aktif otomatis** bila target lint berada di dalam direktori
bernama `skills/` (mis. `python tools/skill-linter/lint.py skills/` atau
subdirektorinya). Repo root di-infer sebagai parent dari `skills/`, dan
`ROUTING.md` dicari di sana. Bila `ROUTING.md` tidak ditemukan, check
dilewati dengan catatan di stderr. Hasil check dilaporkan sebagai satu
entri `ROUTING.md - routing-reference check (FORWARD + REVERSE)` terpisah
dari laporan per-file, dan pelanggarannya membuat exit code = 1.

Konsistensi diperiksa **dua arah**:

- **FORWARD** — setiap nama skill yang dirujuk `ROUTING.md` (token
  kebab-case dalam backtick, mis. `` `idor-and-bola` ``) harus punya
  `skills/**/<name>/SKILL.md`. Kalau tidak:

  ```text
  [routing-reference] FORWARD: ROUTING.md merujuk skill 'x' tetapi skills/**/x/SKILL.md tidak ditemukan ...
  ```

- **REVERSE** — setiap `skills/**/<name>/SKILL.md` harus disebut minimal
  sekali di `ROUTING.md`. Kalau tidak:

  ```text
  [routing-reference] REVERSE: skill 'x' (skills/web/x/SKILL.md) tidak disebut sekali pun di ROUTING.md ...
  ```

Token backtick berikut **dikecualikan** dari FORWARD check:

| Kelompok | Isi |
|---|---|
| Skill deferred — *ditunda sesuai keputusan maintainer* | `cloud-security`, `mobile-security`, `binary-analysis`, `firmware-analysis` |
| Nama kategori `skills/` | `core`, `recon`, `http`, `web`, `api`, `business-logic`, `source`, `specialized` |
| Kosakata status/authorization (ROADMAP §8, §26) | `granted`, `pending`, `confirmed`, `suspected`, `offline-lab` |
| Nama capability allowlist (ROADMAP §5) | `inspect_request`, `request_replay`, dst. |

Isi backtick yang bukan token kebab-case (mis. `scope validation`,
`ROADMAP.md`, `request_replay`) tidak dianggap kandidat nama skill.
Daftar exclusion bisa disesuaikan lewat konstanta `DEFERRED_SKILLS`,
`CATEGORY_NAMES`, dan `STATE_VOCABULARY` di `lint.py`.

## Contoh laporan

```text
skills/core/evidence-handling/SKILL.md
   OK
tests/fixtures/invalid/skill-bad-sections/SKILL.md
   [missing-section] Section H2 wajib tidak ditemukan: 'Stop Conditions'
   [missing-section] Section H2 wajib tidak ditemukan: 'False Positive Checks'
tests/fixtures/invalid/skill-bad-credential/SKILL.md
   [credential-literal] baris 41: kemungkinan credential literal pada 'api_key' (nilai quoted). Simpan di credential store dan rujuk sebagai reference (ROADMAP §23)

Ringkasan: 3 file diperiksa, 1 lolos, 2 gagal
```

## Test

Unit test tersedia di `tests/test_skill_linter.py`. Jalankan dari root project:

```bash
python -m unittest tests.test_skill_linter
python -m unittest discover tests
```

Fixture:

- `tests/fixtures/valid/skill-example-good/SKILL.md` — harus lolos semua aturan;
- `tests/fixtures/invalid/skill-bad-sections/SKILL.md` — gagal karena section H2 hilang;
- `tests/fixtures/invalid/skill-bad-credential/SKILL.md` — gagal karena credential literal.

## Batasan yang diketahui

- Hanya subset YAML sederhana (`key: value`) — tanpa anchor, alias, atau flow
  style; sesuai konvensi frontmatter skill di repo ini.
- Linter memeriksa **struktur dan pola**, bukan substansi metodologi: skill
  yang lolos tetap perlu review isi.
