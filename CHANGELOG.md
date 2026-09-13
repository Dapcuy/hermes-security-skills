# Changelog

Semua perubahan yang menonjol pada project ini didokumentasikan di file ini.

Format mengikuti semangat [Keep a Changelog](https://keepachangelog.com/), penomoran versi mengikuti [Semantic Versioning](https://semver.org/). Bahasa: naskah Indonesia, istilah teknis Inggris.

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
