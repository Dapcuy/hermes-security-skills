# Contributing — Hermes Security Skills

Terima kasih tertarik berkontribusi. Dokumen ini menjelaskan alur kontribusi skill, aturan teknis yang tidak bisa dinegosiasikan, dan kebijakan review keamanan.

Gaya bahasa project: **naskah Indonesia, istilah teknis Inggris**. Ikuti gaya ini di semua konten baru.

## Sebelum Mulai

- Baca `README.md` (visi, prinsip, non-goals) dan `RULES.md` (aturan mutlak).
- Baca `ROADMAP.md` §6 (skill hierarchy), §7 (standard skill format), §7.1 (skill linter).
- Pahami prinsip inti: **skill tidak mengetahui tool** — skill meminta *capability*, bukan menentukan tool.

## Alur Kontribusi Skill

### 1. Tentukan posisi skill

- Cek `ROUTING.md` dan direktori `skills/` — apakah kebutuhan itu sudah tercakup skill yang ada? Duplikasi skill akan ditolak.
- Tentukan tier: core (Tier 1), recon (Tier 2), http proxy (Tier 3), web (Tier 4), api (Tier 5), business logic (Tier 6), source review (Tier 7), specialized (Tier 8). Penambahan mengikuti kebutuhan nyata, bukan jumlah skill.
- Skill baru ditaruh di subdirektori `skills/` yang sesuai (`core/`, `recon/`, `http/`, `web/`, `api/`, `business-logic/`, `source/`, `specialized/`).

### 2. Ikuti standard skill format (ROADMAP §7)

Setiap skill wajib memakai format konsisten dengan frontmatter:

```yaml
---
name: idor-and-bola
description: >
  Use when analyzing object-level authorization,
  cross-account access, or tenant isolation.
version: 0.1.0
risk: medium
requires_credentials: true    # jika butuh test account
---
```

dan section wajib:

```
## Purpose
## When To Use
## When Not To Use
## Authorization Preconditions
## Required Context
## Required Capabilities
## Required Credentials
## Core Concepts
## Reasoning Workflow
## Allowed Operations
## Approval Requirements
## Forbidden Operations
## Evidence Requirements
## False Positive Checks
## Severity Guidance
## Stop Conditions
## Output Format
## Related Skills
```

### 3. Lolos skill-linter (ROADMAP §7.1) — syarat wajib

Semua skill **harus lolos `tools/skill-linter`** yang berjalan otomatis di CI sejak Phase 1. Linter memvalidasi:

- frontmatter schema (name, version, risk);
- semua required sections ada;
- naming convention konsisten;
- tidak ada hardcode tool di luar capability;
- tidak ada credential literal di dalam skill;
- referensi capability valid terjalankan terhadap registry.

CI gagal jika linter gagal — tidak ada pengecualian manual.

### 4. Pull request

1. Buat perubahan kecil dan fokus (satu skill atau satu kelompok perubahan terkait).
2. Jalankan skill-linter secara lokal sebelum submit.
3. Isi deskripsi PR: motivasi, konteks penggunaan, contoh reasoning dry-run di lab lokal (untuk skill baru).
4. Tanggapi review sampai disetujui, lalu merge dilakukan oleh maintainer.

## Aturan Tidak Hardcode Tool

Aturan ini mutlak (ROADMAP §4.1) dan menjadi penyebab penolakan tercepat:

**Boleh** — skill meminta capability abstrak:

```yaml
requires:
  - request_replay
  - response_comparison
```

**Dilarang** — skill menyebut implementasi konkret:

```
gunakan mitmproxy
gunakan curl
gunakan Docker
gunakan nuclei / nmap / burp / caido / ...
```

Provider ditentukan oleh **capability registry**, bukan oleh skill. Alasannya: provider dapat berubah (sudah pernah terjadi: Caido digantikan hermes-proxy) tanpa mengubah satu baris skill. Nama tool boleh muncul hanya di dokumen arsitektural (README, docs/, ROADMAP) — tidak pernah di dalam `skills/`.

Terkait: jangan pernah menaruh credential literal, token, atau API key di dalam skill. Referensi credential ditulis sebagai reference (mis. `accounts: [account-a, account-b]`) — nilai sebenarnya berada di credential store di luar repo.

## Kebijakan Review Keamanan

Kontribusi di project ini adalah kontribusi ke sistem yang mengoperasikan security testing terhadap target nyata. Review diperlakukan sebagai security review:

1. **Setiap PR melewati linter + checklist review.** Untuk skill: kelengkapan section, kewajaran risk classification, kejelasan authorization preconditions, kejelasan forbidden operations, stop conditions, dan false-positive checks.
2. **Perubahan yang menyentuh area sensitif butuh review maintainer khusus** (dua mata, tidak self-merge): `policy/`, `capabilities/`, `runtimes/`, `schemas/`, `tools/`, `docs/security-model.md`, `docs/threat-model.md`, semua `docs/adr/`. Area ini bagian dari trusted computing base atau mengikat perilaku enforcement.
3. **Tidak ada kontribusi yang menambah jalur egress, melemahkan scope validation, atau menambah operasi destructive/exfiltration/credential-attack.** Ini sesuai non-goals project; PR dengan efek tersebut akan ditolak apa pun argumennya.
4. **Konten target tidak pernah masuk repo.** Jangan paste response asli, data sensitif target, atau credential ke issue, PR, skill, knowledge, atau contoh. Gunakan lab lokal (OWASP Juice Shop, DVWA, WebGoat, crAPI, custom lab) untuk semua contoh dan walkthrough.
5. **Perubahan policy tidak boleh dilakukan untuk memuluskan satu engagement tertentu.** Policy adalah security boundary; perubahannya versioned, tercatat di audit log, dan dievaluasi ulang terhadap execution plan yang berjalan.
6. **Laporkan kerentanan pada project ini secara private** ke maintainer, bukan lewat issue publik.

## Checklist Skill Sebelum Submit

- [ ] Frontmatter lengkap (name, description, version, risk, requires_credentials bila relevan)
- [ ] Semua section wajib ada
- [ ] Tidak ada hardcode tool di luar capability
- [ ] Tidak ada credential literal
- [ ] Referensi capability valid terhadap registry
- [ ] Authorization preconditions eksplisit
- [ ] Forbidden operations dan stop conditions eksplisit
- [ ] False-positive checks ada
- [ ] Skill-linter lolos di CI
- [ ] Bahasa: naskah Indonesia, istilah teknis Inggris

## Lisensi Kontribusi

Dengan mengirim kontribusi, kamu menyetujui kontribusimu dilisensikan di bawah lisensi project (MIT — lihat `LICENSE`).
