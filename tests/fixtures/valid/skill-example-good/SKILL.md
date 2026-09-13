---
name: skill-example-good
description: >
  Example skill used by the linter test-suite: a complete, well-formed
  SKILL.md that must pass every rule with no violations.
version: 0.1.0
risk: low
---

# Skill Example Good

## Purpose

- Menjadi fixture valid untuk test skill-linter: struktur lengkap tanpa pelanggaran.
- Menunjukkan bentuk minimal section yang benar sesuai format standar (ROADMAP §7).

## When To Use

- Ketika test suite butuh contoh skill yang harus lolos seluruh aturan linter.
- Ketika menyusun skill baru dan butuh contoh kerangka yang sudah benar.

## When Not To Use

- Bukan skill fungsional untuk engagement nyata — isinya contoh dokumentasi saja.
- Jangan dipakai sebagai template tanpa menyesuaikan konten dengan metodologi yang relevan.

## Authorization Preconditions

- Skill contoh ini tidak melakukan operasi apa pun, jadi tidak ada precondition aktif.
- Dokumentasikan status authorization engagement (`pending`, `granted`, `offline-lab`) sebelum skill lain berjalan.

## Required Context

- Permintaan atau pertanyaan yang melatarbelakangi pemanggilan skill contoh ini.
- Status engagement, bila konteksnya adalah simulasi reasoning.

## Required Capabilities

Tidak ada. Skill contoh ini tidak meminta capability apa pun ke control plane.

## Core Concepts

- Skill punya format baku: frontmatter plus section H2 wajib (ROADMAP §7).
- Skill meminta capability, bukan tool; provider ditentukan registry (ROADMAP §4.1).
- Setiap klaim keamanan harus punya evidence dan FP check sebelum naik status (ROADMAP §25, §26).

## Reasoning Workflow

1. Baca konteks dan tentukan tujuan pemanggilan skill.
2. Ikuti urutan section sebagai kerangka reasoning.
3. Tutup dengan output yang bisa ditindaklanjuti user.

## Allowed Operations

- Reasoning dan dokumentasi lokal.
- Membaca dokumen project yang relevan.

## Approval Requirements

- Tidak ada operasi yang membutuhkan approval karena tidak ada operasi aktif.

## Forbidden Operations

- Operasi jaringan atau eksekusi apa pun dari skill contoh ini.
- Memakai fixture ini sebagai dasar klaim keamanan nyata.

## Evidence Requirements

- Simpan keluaran reasoning sebagai catatan case bila dipakai dalam simulasi.
- Setiap artifact yang dipersist harus ter-sanitasi dari data sensitif (ROADMAP §23).

## False Positive Checks

- Contoh klaim dalam fixture ini tidak boleh diperlakukan sebagai temuan.
- Verifikasi bahwa kesimpulan apa pun punya rujukan evidence sebelum dipakai.

## Severity Guidance

- Fixture ini tidak menghasilkan finding, jadi tidak ada severity.
- Gunakan skala low/medium/high/critical dengan justifikasi ketika menilai temuan nyata.

## Stop Conditions

- Konteks tidak jelas → hentikan reasoning dan minta klarifikasi (ROADMAP §10).
- Kebutuhan keluar dari dokumentasi → alihkan ke skill yang tepat.

## Output Format

- Ringkasan singkat plus langkah berikutnya, dalam markdown terstruktur.

## Related Skills

- `engagement-scoping` — titik mulai engagement nyata.
- `hypothesis-management` — contoh skill reasoning yang sesungguhnya.
