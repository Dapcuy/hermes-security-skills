# Changelog

Semua perubahan yang menonjol pada project ini didokumentasikan di file ini.

Format mengikuti semangat [Keep a Changelog](https://keepachangelog.com/), penomoran versi mengikuti [Semantic Versioning](https://semver.org/). Bahasa: naskah Indonesia, istilah teknis Inggris.

## [Unreleased] — v3.0 (Web/API focused + Skill-First + Knowledge Base)

Revisi arsitektural besar mengikuti ROADMAP v3.0: fokus Web/API (ADR-012), skill sebagai komponen utama, **memory dihapus sebagai komponen** dan diganti Knowledge Base curated (§23–§24).

### Changed

- **Memory dihapus sebagai komponen utama — diganti Knowledge Base curated (§23, §24, §61).** Direktori `memory/` dihapus seluruhnya; state kasus kini hidup di **evidence + jobs + approval + events**, bukan di "memori agent". Package `internal/memory` di-rename + refactor menjadi `internal/knowledge` (Entry/Store/Search + lifecycle captured→normalized→proposed→reviewed→trusted→stale→archived tetap); komponen case-memory (`IngestFromTarget`, `Retention`, dedup-per-case, penanganan `memory/cases`) dihapus. Knowledge firewall baru (§20/§23): `knowledge ingest` **menolak fail-closed** entry dengan `provenance.source: target-controlled` (atau trust untrusted) — konten target hidup di evidence, tidak pernah masuk knowledge base; promosi `reviewed`/`canonical` hanya lewat human review.
- **Knowledge base di-restrukturisasi (§23):** direktori resmi kini `knowledge/{canonical, research, methodology, false-positives, reviewed}` (+ README per direktori: isi yang sah, siapa yang menulis, aturan provenance). Hasil ingest masuk `knowledge/research/` (state proposed); review memindahkan ke `knowledge/reviewed/`; promosi ke `canonical/` adalah keputusan owner; direktori `proposed/` lama dihapus. Entry `lesson-sqli-boolean-differential` direlokasi dari `memory/cases/juice-demo/` ke `knowledge/methodology/` (state `reviewed`, provenance tetap, catatan relokasi v3.0).
- **CLI knowledge/case diperbarui:** `knowledge ingest/list/search/review/stale` kini berjalan di atas `internal/knowledge` dengan filter `--category` pada `knowledge list`; `case archive` (retention berbasis case memory) **dihapus** — case retention kini adalah jobs cleanup: `case clean <id> [--force]` menghapus `jobs/<case>` (tanpa `--force` = dry-run fail-closed; audit/approval tidak disentuh). `case brief`/`case list` tidak berubah.
- **Skill hierarchy v3.0:** skill dijadikan komponen utama; rename `http-proxy-*` → `http-*`, kategori `recon/` → `discovery/`, `llm-security` → `llm-api-security`, ditambah 3 skill baru; struktur kategori konsolidasi menjadi `core, http, web, api, business-logic, discovery, specialized` (§8, §48).
- **Capability registry dirapikan menjadi 8 capability generik (§12):** `inspect_request, request_replay, request_mutation, response_comparison, endpoint_discovery, template_based_validation, openapi_analysis, json_diff` — capability lama yang terikat tool spesifik (`subfinder_enum`, `httpx_probe`, `nmap_scan`, `ffuf_fuzz`) dan `list_history` dihapus; risk/approval per tool kini ditentukan Tool Registry.
- **Tool Registry baru (`tools/registry.yaml`, ADR-011):** third-party tool diperlakukan sebagai untrusted supply-chain dependency — identitas, versi, digest, signature, risk, capability mapping, dan approval requirement per tool ditentukan registry; katalog seperti `hackingtool` hanya kandidat referensi, bukan dependency runtime.
- **MCP tools di-namespace `security.*`** (`security.validate_scope`, `security.request_replay`, dst.) sesuai kontrak integrasi §6.
- **ADR baru:** ADR-011 (Tool supply-chain architecture) dan ADR-012 (Web/API scope boundary — wireless/mobile/binary/firmware ditunda; discovery tetap in-scope sebagai bagian metodologi Web/API). Dokumen security-model dan threat-model diperbarui (firewall knowledge baru + threat "knowledge poisoning via target content").

### Removed

- **Direktori `memory/` dihapus seluruhnya** (README + `cases/` + `global/`) bersama seluruh konsep case memory: `Store.IngestFromTarget`, `Store.Retention`, dedup-per-case, dan jalur programatik konten target ke pipeline knowledge. State kasus kini eksklusif di evidence/jobs/approval/events (§24).
- **Empat capability lama ter-tool-spesifik dihapus dari registry** (digantikan pemetaan generik via Tool Registry — lihat Changed).

## [2.2.0] — Tool images, case brief, ekspansi skill (pra-v3.0)

### Added

- **Empat tool image pihak ketiga (§13.1):** `hermes-tool-subfinder` (enumerasi subdomain pasif), `hermes-tool-httpx` (probing HTTP), `hermes-tool-nmap` (port scan mode `-sT`), `hermes-tool-ffuf` (directory fuzzing dengan wordlist ter-bake ke image, di-pin per tag SecLists) — semuanya satu tool = satu image, versi di-pin saat build, dibungkus wrapper fail-closed yang menormalisasi output ke validation-result.json + provenance.
- **Lima skill pentest baru:** `subdomain-enumeration`, `subdomain-takeover`, `port-scanning`, `technology-probing` (recon), dan `directory-fuzzing` (web).
- **`hermes-security case brief --case <id>`** — ringkasan konteks satu case dalam satu output: status workspace `jobs/<case>/` (aktif/aborted), approval store (state aktif/revoked/expired/habis + sisa budget), dan statistik event index (jumlah request per method, rentang waktu, evidence terakhir + sha256) — plus catatan eksplisit bila sumber data kosong.
- **`hermes-security case list`** — daftar semua case dari `jobs/` beserta statusnya (direktori evidence dikecualikan).
- **Alur `case_id` end-to-end (memory diperkuat):** POST `/execute` hermes-proxy menerima field opsional `case` (slug `[a-z0-9-]` maks 64, ditolak fail-closed bila invalid); evidence file membawa `case_id`; index event store (`internal/events`) mengisi field `case_id` dan `list_history` menerima filter opsional `case`; MCP `request_replay` meneruskan `case` ke proxy sehingga evidence + index terlabel per engagement.
- **15 skill baru (gelombang ekspansi Tier 3–8):**
  - `skills/web/`: `ssrf-analysis`, `injection-analysis`, `xss-analysis`, `csrf-analysis`, `file-upload-security`, `cors-analysis`;
  - `skills/api/`: `rest-api-testing`, `api-rate-limit-analysis`, `jwt-and-token-analysis`, `graphql-security`, `webhook-and-callback-security`;
  - `skills/http/`: `http-proxy-auth-flow-analysis`, `http-proxy-browser-traffic-analysis`;
  - `skills/specialized/`: `skill-supply-chain-review` (review skill/tool provider image pihak ketiga sebelum diadopsi — tanpa capability aktif) dan `novelty-assessment` (klasifikasi kebaruan temuan sesuai §28 — tidak pernah menyatakan zero-day otomatis; capability `list_history` opsional). Total skill kini 63.
- **Linter routing-reference check (§7.1, permintaan owner):** `tools/skill-linter/lint.py` kini memvalidasi konsistensi dua arah `ROUTING.md` <-> `skills/**/SKILL.md` saat linting direktori `skills/` — FORWARD: setiap skill yang dirujuk ROUTING.md harus punya `skills/**/<name>/SKILL.md`; REVERSE: setiap SKILL.md harus disebut minimal sekali di ROUTING.md. Skill deferred (`cloud-security`, `mobile-security`, `binary-analysis`, `firmware-analysis` — ditunda sesuai keputusan maintainer), nama kategori, kosakata status, dan capability allowlist dikecualikan.
- **Prinsip memory owner (dokumentasi):** `memory/README.md` dan `knowledge/README.md` kini menegaskan memory hanya untuk state kasus, keputusan, evidence reference, dan approval — metodologi security TIDAK disimpan di memory/knowledge; metodologi hidup di skills/ (curated, versioned, lolos linter). Generalisasi metodologi dari pelajaran kasus ditulis sebagai SKILL.md baru.

### Changed

- **Relokasi entry metodologi ke case memory (sesuai prinsip owner).** `knowledge/reviewed/lesson-sqli-boolean-differential.md` dipindah ke `memory/cases/juice-demo/` — itu pelajaran spesifik-kasus engagement Juice Shop, bukan metodologi (teknik boolean differential sudah ter-cover di `skills/web/injection-validation`). Frontmatter disesuaikan (`state: captured`) dan diberi catatan relokasi bertanggal.
- **ROUTING.md dilengkapi** rute untuk skill yang belum ter-route (`payload-selection`, `controlled-fuzzing`, `injection-validation`, `waf-analysis`, `behavioral-anomaly-analysis`) — tertangkap oleh routing-reference check arah REVERSE; rute 15 skill baru telah lengkap.

### Removed

- **Direktori `labs/` dihapus pasca-benchmark (keputusan owner).** Repo fokus pada skill + tool + runtime; kebutuhan lab environment mendatang dipisah ke repo terdedikasi. Makefile tidak lagi punya target `lab-up`/`lab-down`; hasil benchmark tetap permanen di `benchmarks/RESULTS.md` (reproduksi: siapkan target sendiri).

## [2.1.0] — Caido digantikan hermes-proxy

Revisi arsitektur proxy. Perubahan utama:

### Changed

- **Caido & Caido MCP dihapus total** — diganti **hermes-proxy**: interception proxy self-hosted yang berjalan sebagai ephemeral Docker container (curated image, versioned + signed), pola sama dengan validator image. Tidak ada lagi jembatan ke tool pihak ketiga untuk operasi HTTP (ROADMAP §11, ADR-002).
- **Proxy container menjadi satu-satunya komponen dengan privilege egress.** Validator tetap `network: none`; post-MVP validator yang butuh egress di-route melalui proxy (Validator -> hermes-proxy -> destination) (ROADMAP §5.2, §16, ADR-010).
- **Pendekatan bertahap untuk proxy.** MVP: replay/mutation engine (tanpa TLS MITM, tanpa intercept traffic browser). Full interception + capture traffic browser menjadi phase terpisah setelah MVP (Mode 2) (ROADMAP §11).
- **Third-Party Tool Images diperkenalkan (§13.1).** Tool eksternal (nuclei, nmap) masuk hanya sebagai image terkurasi terpisah — satu tool = satu image, versi di-pin saat build CI, dibungkus wrapper policy fail-closed + normalisasi output menjadi evidence dengan provenance; bukan toolbox gabungan.

### Removed

- **Tanpa token eksternal** — tidak ada lagi token Caido / OAuth flow yang dikelola manual. Satu-satunya kredensial internal adalah control-channel token ephemeral per-engagement yang di-generate otomatis oleh control plane, mati bersama container, dan tidak pernah terlihat Hermes (ROADMAP §11, §23).

### Added

- Control channel internal control plane <-> hermes-proxy: token ephemeral per-engagement, hanya listen di Docker network internal, tidak di-expose ke luar.
- Policy bundle in-line di proxy container: di-mount read-only (hash-verified), setiap request dievaluasi di dalam proxy sebelum dikirim, dengan TOCTOU re-validation saat eksekusi dan perilaku fail-closed (bundle tidak valid = tolak semua operasi).
- ADR direvisi: ADR-002 (hermes-proxy menggantikan Caido MCP) dan ADR-010 (network=none + egress via proxy) diperbarui mengikuti keputusan baru.

## [2.0.0] — Revisi menyeluruh model keamanan

Revisi besar desain project. Perubahan utama:

### Added

- **Enforcement model eksplisit (ROADMAP §4.2, ADR-007).** Perbedaan tegas antara guardrail **advisory** (Phase 1–3 — markdown instruction, kepatuhan bergantung disiplin model, bukan security boundary) dan **enforced** (Phase 4+ — dieksekusi di tool path, Hermes secara teknis tidak bisa mem-bypass karena satu-satunya jalan ke provider adalah melalui control plane). Integration contract berbasis **MCP server mode** (`hermes-security serve --mcp`); Hermes hanya melihat MCP tool yang sudah melalui allowlist, dan setiap tool berisiko mengeksekusi policy check sebelum provider dipanggil. Deployment prerequisites Hermes didokumentasikan sebagai syarat penggunaan (ROADMAP §4.4).
- **Credential provider sebagai komponen arsitekturnya sendiri (ROADMAP §23, ADR-009).** Kredensial disimpan di credential store terpisah (OS keychain / encrypted external), tidak pernah masuk konteks LLM. Skill dan approval hanya merujuk *reference*; injection dilakukan control plane saat eksekusi; sanitasi otomatis evidence/log/result terjadi sebelum data menyentuh reasoning context.
- **Prompt injection & content trust sebagai first-class concern (ROADMAP §24, ADR-008).** Target-controlled content adalah data, bukan instruksi. Mekanisme: structural separation, content quarantine, context budget, knowledge firewall (konten target tidak menulis ke knowledge/canonical), policy firewall (tidak ada jalur dari konten target ke policy/, capabilities/, runtimes/), injection detection, dan adversarial test suite wajib sejak Phase 4.
- **Manual abort / kill switch (ROADMAP §10).** `hermes-security abort --case <case-id>`: revoke semua approval aktif, hentikan queue execution, kill container Docker yang berjalan (validator DAN hermes-proxy), hentikan replay, tandai case sebagai aborted di memory, tinggalkan audit entry.
- **Exit criteria per phase dan target metrik** (ROADMAP §31–§42, §43): termasuk scope violation count = 0, destructive action count = 0, container cleanup success = 100%, prompt injection success = 0.
- **Policy integrity (ROADMAP §8):** policy files versioned, perubahan tercatat di audit log, perubahan policy di tengah engagement dievaluasi ulang terhadap execution plan yang berjalan.
- **Approval revocation & renewal (ROADMAP §9):** approval dapat dicabut kapan saja; tidak ada silent extension — renewal selalu approval baru dengan audit trail terpisah.
- **Evidence integrity & retention (ROADMAP §25):** evidence di-hash (sha256), audit log append-only dengan chain hash (tamper-evident), sanitasi kredensial sebelum persist, retention policy saat engagement berakhir.
- **ADR baru:** ADR-007 (enforcement & integration contract), ADR-008 (prompt injection & content trust), ADR-009 (credential provider), ADR-010 (docker network mode).
- Dukungan **macOS** (Docker Desktop) sebagai target platform selain Linux dan Windows.

### Changed

- **Docker network model diklarifikasi (ROADMAP §16, ADR-010).** MVP memakai `network: none` untuk validator — satu-satunya mode yang didukung; validator tidak melakukan fetch ke manapun. Egress kontrol dijadwalkan eksplisit sebagai escalation (route melalui hermes-proxy, post-MVP), bukan asumsi. Test wajib: container yang mencoba akses jaringan harus gagal — bagian dari acceptance criteria.
- Inkonsistensi diperbaiki: duplikasi skill, naming drift, dukungan macOS, python-validator.
- Trust boundary diperjelas: control plane Go adalah **trusted computing base** (ROADMAP §20) — kompromi control plane = kompromi seluruh isolation.

## [1.0.0] dan sebelumnya

Riwayat versi awal tidak didokumentasikan ulang di file ini; lihat `ROADMAP.md` untuk spesifikasi terkini.
