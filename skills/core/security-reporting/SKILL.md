---
name: security-reporting
description: >
  Use when a validated finding must be written up: structured report with
  reproduction steps, impact, and remediation, severity justified by real
  impact, and submission that always waits for explicit human approval.
version: 0.1.0
risk: low
---

# Security Reporting

## Purpose

- Menyusun report berkualitas dengan struktur baku: reproduction, impact, remediation, plus severity yang dijustifikasi.
- Memastikan report hanya ditulis dari finding yang lolos false-positive analysis dan punya evidence minimum (ROADMAP §25, §26).
- Menjaga prinsip tanpa auto-submit: pengiriman ke program adalah keputusan manusia, selalu (ROADMAP §2).

## When To Use

- Finding mencapai status `reproduced` atau `confirmed`, atau `inconclusive` yang memang perlu dilaporkan apa adanya.
- User meminta laporan atau draft pengunguman untuk program.
- Report lama perlu direvisi karena evidence atau severity berubah.

## When Not To Use

- Hypothesis masih `needs-validation` dan belum lewat validasi.
- FP analysis belum berjalan atau masih menyisakan faktor yang tidak terjawab.
- Menulis report bukan alasan untuk melakukan testing tambahan — kebutuhan data baru kembali ke skill validasi.

## Authorization Preconditions

- Semua data dalam report sudah disanitasi dari kredensial dan data sensitif (ROADMAP §23, §25).
- Disclosure mengikuti aturan program: scope, kanal, dan kebijakan publikasi.
- Tidak ada auto-submit dalam kondisi apa pun — report yang selesai pun menunggu keputusan manusia (ROADMAP §2).

## Required Context

- Finding record lengkap dengan status lifecycle dan referensi evidence.
- Minimum evidence set dari evidence-handling.
- Aturan program: kanal submission, kebijakan disclosure, batasan publikasi.
- Severity guidance beserta konteks bisnis target.

## Required Capabilities

Tidak ada capability yang dibutuhkan skill ini. Report disusun sepenuhnya dari finding dan evidence yang sudah ada. Tidak ada pengiriman apa pun ke program, kanal, atau pihak ketiga dari dalam skill ini — pengiriman adalah tindakan manusia setelah approval. Prinsip capability-over-tool tetap berlaku bila kelak report dirender ke format lain (ROADMAP §4.1).

## Core Concepts

- **Struktur report baku**: summary, reproduction steps, expected vs actual behavior, impact, remediation, severity + justifikasi, referensi evidence, scope reference, confidence.
- **Human approval**: submission, publikasi, dan disclosure selalu butuh keputusan manusia; agent tidak pernah mengirim sendiri (ROADMAP §2).
- **Novelty classification**: temuan yang diduga novel mengikuti alur §28 — jangan menyebut zero-day tanpa proses (ROADMAP §28).
- **Evidence by reference**: report merujuk evidence lewat hash dan path, bukan menempelkan data mentah.

## Reasoning Workflow

1. Kumpulkan finding record dan pastikan minimum evidence set terpenuhi.
2. Tulis reproduction steps bernomor yang bisa diulang orang lain, dengan request minimal yang perlu.
3. Rumuskan impact dalam dampak nyata bagi pemilik target, bukan teknik eksploitasi.
4. Tulis remediation yang konkret dan bisa dieksekusi developer.
5. Tetapkan severity dengan guidance dan justifikasi eksplisit.
6. Ringkas hasil false-positive analysis dan confidence.
7. Serahkan draft ke user untuk review; jalur disclosure lanjutan lewat responsible-disclosure bila diminta.

## Allowed Operations

- Menulis dan merevisi draft report di case memory.
- Membaca finding, evidence, dan knowledge yang relevan.
- Rekomendasi severity beserta justifikasinya.

## Approval Requirements

- Submission atau pengunguman ke program WAJIB menunggu human approval eksplisit; tidak ada pengecualian.
- Skill ini tidak pernah mengirim data ke mana pun — mengirim adalah aksi manusia di luar reasoning.
- Permintaan user untuk "langsung submit" dijawab dengan penjelasan kebijakan approval, bukan kepatuhan otomatis.

## Forbidden Operations

- Auto-submit ke program, kanal disclosure, atau pihak ketiga.
- Menyatakan `confirmed` untuk finding yang belum mencapai status tersebut di lifecycle (ROADMAP §26).
- Memasukkan kredensial, data sensitif, atau payload yang belum diredaksi ke dalam report.
- Mengklaim zero-day atau membuat publikasi prematur (ROADMAP §2, §28).

## Evidence Requirements

- Report merujuk evidence lewat hash + path; klaim tanpa rujukan evidence tidak boleh tampil sebagai fakta.
- Reproduction steps harus bisa diulang reviewer dengan informasi yang ada di report sendiri.
- Sertakan ringkasan FP analysis dan confidence sebagai bagian dari report.

## False Positive Checks

- Cek ulang sebelum menulis: apakah FP checklist sudah lolos dan tersisih semua faktornya?
- Apakah impact nyata terjadi, atau masih asumsi yang belum dibuktikan?
- Apakah reproduction deterministik, atau flaky dan hanya berhasil sesekali?

## Severity Guidance

- Gunakan skala konsisten (low/medium/high/critical) dengan justifikasi: dampak, prasyarat authentication, kemudahan eksploitasi, dan cakupan scope.
- Severity naik karena dampak nyata yang terbukti, bukan karena kerumitan teknik.
- Bila evidence tidak mendukung dampak yang diklaim, turunkan severity atau kembali ke validasi.

## Stop Conditions

- Minimum evidence set tidak terpenuhi → jangan lanjut ke report; kembali ke validasi (ROADMAP §25).
- User menekan untuk submit tanpa review → jelaskan kebijakan human approval dan berhenti di draft (ROADMAP §2).
- Temuan berpotensi novel high-impact → ikuti alur §28: stop active testing, simpan evidence minimum, redact, mark potentially-unknown, inform user (ROADMAP §28).

## Output Format

- Report markdown terstruktur: summary, reproduction, impact, remediation, severity + justifikasi, evidence references, FP summary, confidence.
- Draft disertai daftar hal yang masih perlu keputusan atau konfirmasi manusia.

## Related Skills

- `evidence-handling` — sumber evidence dan sanitasi yang dipakai report.
- `responsible-disclosure` — jalur disclosure setelah human approval.
- `vulnerability-validation`, `false-positive-analysis` — penentu kualitas temuan yang dilaporkan.
