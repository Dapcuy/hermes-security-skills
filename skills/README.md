---
name: skills-index
description: >
  Use when navigating the skills/ directory: the map of all skill
  categories per tier (ROADMAP §6), what each category covers, and how
  to pick the right starting point before loading a specific skill.
version: 0.1.0
risk: low
---

# Skills Index

## Purpose

- Menjadi peta kategori `skills/`: kategori apa saja yang ada, tier berapa, dan apa cakupan masing-masing (ROADMAP §6).
- Membantu memilih kategori awal sebelum memuat skill spesifik, sehingga routing tidak menebak dari nama file.
- Menyatakan total dan jumlah skill per kategori sebagai snapshot kondisi repo.
- Menegaskan aturan umum yang berlaku untuk semua skill: format standar §7, wajib lolos skill-linter §7.1, dan skill hanya meminta capability (ROADMAP §4.1).

## When To Use

- Baru membuka repo dan perlu gambaran kategori skill yang tersedia.
- Gejala di tangan belum jelas masuk kategori mana — gunakan peta ini sebagai pintu masuk sebelum detail di ROUTING.md.
- Menambahkan skill baru dan perlu menentukan direktori kategori yang tepat.
- Memeriksa konsistensi jumlah skill per kategori terhadap struktur direktori.

## When Not To Use

- Sebagai pengganti ROUTING.md: pemetaan gejala → skill yang operasional ada di sana; peta ini hanya level kategori.
- Sebagai dasar authorization — dokumen ini tidak memberi izin apa pun terhadap target (ROADMAP §8).
- Mencari metodologi detail sebuah skill — langsung buka SKILL.md pada kategorinya.
- Untuk keputusan policy atau capability — sumber kebenarannya adalah policy/ dan capabilities/registry.yaml.

## Authorization Preconditions

- Tidak ada operasi terhadap target pada dokumen ini, sehingga tidak ada precondition aktif.
- Dokumen bersifat referensi statis: membaca dan menavigasi struktur skills/ tidak memerlukan status authorization.
- Semua pertimbangan authorization tetap dimulai dari engagement-scoping, bukan dari halaman ini.

## Required Context

- Struktur direktori `skills/` saat ini dan daftar tier pada ROADMAP §6.
- ROUTING.md untuk pemetaan gejala → skill yang lebih rinci.
- capabilities/registry.yaml sebagai daftar capability yang valid (ROADMAP §5).
- tools/skill-linter sebagai validator format untuk setiap SKILL.md (ROADMAP §7.1).

## Required Capabilities

Tidak ada capability aktif yang diperlukan. Halaman ini adalah dokumentasi navigasi murni: membaca struktur repo dan mengarahkan pemilihan skill, tanpa operasi jaringan maupun eksekusi (ROADMAP §4.1, §8).

## Core Concepts

- **core/** (Tier 1): fondasi setiap engagement — scoping, routing, hypothesis, validation, false-positive analysis, evidence, dan reporting.
- **recon/** (Tier 2): pemetaan permukaan tanpa menyentuh target — recon pasif dari sumber publik, ekstraksi endpoint dari data terekam, fingerprint teknologi, dan prioritisasi permukaan; `web-surface-mapping` yang satu tier dengannya berada di `web/`.
- **http/** (Tier 3, placeholder): metodologi operasi HTTP melalui capability proxy — traffic analysis, replay, mutation, comparison, auth flow, capture browser.
- **web/** (Tier 4): analisis keamanan aplikasi web per kelas kerentanan — authorization, IDOR/BOLA, injection, SSRF, CSRF, upload, misconfiguration, dan validasi payload.
- **api/** (Tier 5, placeholder): metodologi keamanan API — methodology, OpenAPI, REST, GraphQL, token, rate limit, dan webhook.
- **business-logic/** (Tier 6): kerentanan yang tak tertangkap scanner — workflow, transaksi, replay, race condition, isolasi multi-tenant, dan vulnerability chaining.
- **source/** (Tier 7): review source code yang sepenuhnya pasif — triage codebase, review authorization, data flow server-side, deteksi secret, dan risiko dependensi; tanpa capability aktif.
- **specialized/** (Tier 8): domain khusus sesuai kebutuhan nyata — keamanan integrasi LLM, keamanan MCP, dan responsible disclosure.

## Reasoning Workflow

1. Tentukan konteks: engagement baru, target web/API, kode sumber, atau domain khusus.
2. Petakan konteks ke kategori: fondasi → core; pemetaan permukaan awal → recon; permukaan web → web; API → api; operasi HTTP → http; kode tersedia → source; domain khusus → specialized.
3. Buka SKILL.md pada kategori terpilih; pastikan prasyaratnya (authorization, context, capability) terpenuhi.
4. Bila gejala masih ambigu, lanjutkan ke ROUTING.md untuk pemetaan per-gejala.
5. Selalu mulai dari engagement-scoping untuk engagement baru — tanpa kecuali.

## Allowed Operations

- Membaca struktur skills/ dan merujuk SKILL.md pada kategori terkait.
- Memperbarui tabel snapshot pada Output Format saat skill baru ditambahkan.
- Menambahkan kategori baru hanya bila ROADMAP §6 mendefinisikannya.

## Approval Requirements

- Tidak ada approval: dokumen ini tidak melakukan operasi apa pun (ROADMAP §8).
- Perubahan isi peta cukup melalui review normal repo; tidak menyentuh policy maupun capability registry (ROADMAP §4.3).
- Penambahan kategori yang tidak ada di ROADMAP §6 wajib dikonsultasikan dulu, bukan langsung dibuatkan direktorinya.

## Forbidden Operations

- Memperlakukan halaman ini sebagai authorization, scope, atau batasan engagement.
- Mengubah definisi tier atau daftar skill resmi di luar ROADMAP §6.
- Mencantumkan capability yang tidak terdaftar di registry pada referensi skill mana pun.
- Menaruh data target, kredensial, atau evidence di dalam dokumen ini (ROADMAP §23, §25).

## Evidence Requirements

- Tabel kategori pada Output Format mencantumkan jumlah skill per kategori dan tanggal/kondisi snapshot-nya.
- Kategori yang masih placeholder ditandai eksplisit agar pembaca tahu isinya belum lengkap.
- Setiap klaim aturan merujuk sumbernya (ROADMAP §7, §7.1, §4.1).

## False Positive Checks

- Jumlah skill bergerak: kategori yang sedang diisi bisa berubah antar pembacaan — verifikasi langsung ke direktori, jangan percaya snapshot mentah-mentah.
- Direktori yang ada belum tentu berisi skill lengkap sesuai tier-nya; cek SKILL.md yang benar-benar tersedia.
- Nama kategori bukan jaminan cakupan; baca frontmatter dan Purpose SKILL.md sebelum menyimpulkan fungsi skill.

## Severity Guidance

- Dokumen ini tidak menghasilkan finding sehingga tidak menetapkan severity.
- Salah pilih kategori berdampak ke efisiensi routing; koreksinya murah selama belum ada operasi terhadap target.
- Kesalahan paling mahal tetap sama: memulai operasi aktif sebelum authorization — itu dinilai fatal, bukan sekadar salah kategori (ROADMAP §8).

## Stop Conditions

- Isi peta bertentangan dengan ROADMAP §6 atau ROUTING.md → ROADMAP adalah sumber kebenaran; tandai peta perlu diperbarui.
- Struktur skills/ berubah signifikan sejak snapshot → perbarui tabel sebelum dipakai untuk navigasi.
- Kebutuhan kategori baru muncul yang belum ada di ROADMAP §6 → stop dan eskalasi sebagai keputusan roadmap, bukan keputusan lokal.

## Output Format

| Kategori | Tier | Isi | Jumlah skill |
|---|---|---|---|
| `core/` | 1 | Fondasi setiap engagement: scoping, routing, hypothesis, validation, false-positive analysis, evidence, dan reporting. | 7 |
| `recon/` | 2 | Pemetaan permukaan tanpa menyentuh target: recon pasif dari sumber publik, ekstraksi endpoint dari data terekam, fingerprint teknologi, prioritisasi permukaan. | 4 |
| `http/` | 3 | (Placeholder) metodologi operasi HTTP melalui capability proxy: traffic analysis, replay, mutation, comparison. | 4 |
| `web/` | 4 | Analisis keamanan aplikasi web per kelas kerentanan: authorization, injection, SSRF, CSRF, misconfiguration, validasi payload. | 10 |
| `api/` | 5 | (Placeholder) metodologi keamanan API: methodology, OpenAPI, REST, GraphQL, token, rate limit, webhook. | 2 |
| `business-logic/` | 6 | Kerentanan yang tak tertangkap scanner: workflow, transaksi, replay, race condition, isolasi multi-tenant, vulnerability chaining. | 8 |
| `source/` | 7 | Review source code yang sepenuhnya pasif: triage codebase, review authorization, data flow server-side, deteksi secret, risiko dependensi. | 5 |
| `specialized/` | 8 | Domain khusus yang ditambahkan sesuai kebutuhan nyata: keamanan integrasi LLM, keamanan MCP, responsible disclosure. | 3 |

**Total: 43 skill** (snapshot kondisi repo saat dokumen ini terakhir diperbarui; lihat False Positive Checks).

## Related Skills

- `security-task-routing` — pemilihan skill berbasis gejala yang operasional.
- `engagement-scoping` — titik masuk wajib setiap engagement sebelum skill lain berjalan.
- Semua SKILL.md pada delapan kategori di atas — halaman ini hanya peta, bukan penggantinya.
