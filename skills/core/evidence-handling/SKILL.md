---
name: evidence-handling
description: >
  Use when observations or validation results must be stored as evidence:
  enforcing the minimum evidence set, sanitizing credentials BEFORE
  persistence, and attaching sha256 hashes and provenance to every artifact.
version: 0.1.0
risk: low
---

# Evidence Handling

## Purpose

- Menyimpan bukti sesuai arsitektur evidence (ROADMAP §25): minimum set lengkap, terstruktur, dan berkaidah.
- Menjamin sanitasi kredensial terjadi SEBELUM data dipersist dan sebelum menyentuh reasoning context (ROADMAP §23).
- Menjaga integritas evidence lewat hash sha256 dan provenance pada setiap artifact.

## When To Use

- Setiap observation atau hasil validasi menghasilkan data yang perlu disimpan.
- Sebelum data dari provider masuk ke reasoning context.
- Sebelum report disusun, untuk memastikan evidence minimum terpenuhi.
- Saat authorization expired atau engagement selesai, untuk menjalankan retention policy (ROADMAP §25).

## When Not To Use

- Bukan untuk mengumpulkan data mentah tanpa tujuan — evidence tanpa klaim yang dilayaninya hanya beban.
- Bukan tempat menyimpan kredensial; credential store ada di luar repo dan di luar skill ini (ROADMAP §23).
- Bukan pengganti sanitasi otomatis di control plane — skill ini mengelola evidence, bukan mem-bypass jalur sanitasi.

## Authorization Preconditions

- Evidence yang berasal dari operasi aktif hanya sah bila operasinya berjalan di dalam authorization dan approval yang berlaku.
- Saat authorization expired atau engagement selesai, case data masuk retention policy: redact/hapus data sensitif sesuai kesepakatan (ROADMAP §25).
- Penyimpanan berhenti sebagai jalur analisis bila policy berubah menjadi deny di tengah jalan (ROADMAP §10).

## Required Context

- Sumber data: event store proxy atau hasil validator Docker, beserta id case-nya.
- Kredensial aktif pada engagement, agar field yang harus disanitasi diketahui.
- Schema evidence project (hash, provenance, referensi) yang menjadi format target.
- Status engagement: aktif, selesai, atau retention.

## Required Capabilities

- `list_history` — membaca riwayat request/response yang terekam pada event store (read-only).

Skill ini tidak meminta capability aktif lain. Penarikan data baru lewat replay bukan bagian dari skill ini — ia hanya membaca apa yang sudah terekam, lalu mengolahnya menjadi evidence berkaidah.

## Core Concepts

- **Minimum evidence set (ROADMAP §25)**: baseline, reproduction steps, expected behavior, actual behavior, impact, false-positive analysis, scope reference, confidence, sanitized artifact.
- **Integrity**: setiap evidence di-hash sha256 saat dibuat; audit log append-only dengan chain hash sehingga tampering terdeteksi (ROADMAP §25).
- **Provenance**: setiap artifact mencatat sumber (proxy/validator), tool dan versinya bila relevan, dan waktu pembuatan.
- **Sanitasi dulu, persist kemudian**: sanitasi kredensial terjadi SEBELUM persist dan SEBELUM data masuk reasoning context (ROADMAP §23).
- **Context budget**: body besar disimpan sebagai evidence reference (hash + path), bukan inline di reasoning (ROADMAP §24).

## Reasoning Workflow

1. Tentukan minimum evidence yang dibutuhkan klaim yang sedang dilayani.
2. Tarik data dari event store lewat list_history atau terima hasil validator yang dinormalisasi.
3. Sanitasi field kredensial: header Authorization, Cookie, Set-Cookie, dan api key diganti marker redaksi — sebelum persist.
4. Hitung hash sha256 pada artifact final (setelah sanitasi) dan catat provenance lengkap.
5. Simpan artifact ke lokasi case, lalu rujuk lewat reference (hash + path), bukan inline dump.
6. Saat engagement berakhir, terapkan retention policy: redact data sensitif target, sisakan anonymized lesson (ROADMAP §25).

## Allowed Operations

- Membaca history dan hasil validator yang sudah dinormalisasi.
- Menulis evidence terstruktur beserta hash dan provenance.
- Redaksi field sensitif pada artifact sebelum disimpan.

## Approval Requirements

- Tidak ada operasi aktif ke target, sehingga tidak ada approval operasional.
- Redaksi atau penghapusan permanen dalam retention policy sebaiknya tercatat di audit trail agar bisa dijelaskan (ROADMAP §25).

## Forbidden Operations

- Menyimpan nilai kredensial di evidence, log, report, memory, atau knowledge (ROADMAP §23).
- Mempersist data mentah sebelum sanitasi.
- Memodifikasi evidence yang sudah di-hash — koreksi berarti artifact baru dengan hash baru.
- Memasukkan body besar mentah ke reasoning context, melanggar context budget (ROADMAP §24).

## Evidence Requirements

- Setiap evidence mencantumkan: hash sha256, provenance (sumber, tool/versi, waktu), referensi ke request/response sumber, dan status sanitasi.
- Klaim tanpa minimum evidence set tidak boleh dinaikkan statusnya di finding lifecycle.
- Chain hash pada audit log dipertahankan; jangan ada jalur tulis yang memotongnya.

## False Positive Checks

- Pastikan sanitasi tidak mengubah makna evidence — redaksi jangan menyentuh parameter yang justru menjadi bukti.
- Hash dihitung pada artifact final setelah sanitasi; hash atas versi pra-sanitasi tidak berarti apa-apa.
- Pastikan evidence merujuk scope entry yang benar; evidence dari luar scope tidak sah dipakai.

## Severity Guidance

- Evidence tidak menaikkan severity temuan; ia menopang (atau meruntuhkan) confidence.
- Evidence minimum yang tidak lengkap menurunkan confidence, dan bisa menggagalkan kenaikan status lifecycle.

## Stop Conditions

- Data berisi kredensial yang tidak bisa disanitasi dengan aman → jangan persist; laporkan ke user dan tangani lewat credential provider (ROADMAP §23).
- Authorization expired → hentikan akumulasi evidence baru dan masuk retention policy (ROADMAP §10, §25).
- Chain hash atau audit log menunjukkan anomali → berhenti dan laporkan, jangan menimpa dengan tulisan baru.

## Output Format

- Evidence record: id, hash sha256, provenance, referensi sumber, ringkasan isi, path artifact sanitized, dan status sanitasi.
- Daftar evidence per klaim (checklist minimum set) yang menunjukkan mana yang terpenuhi.

## Related Skills

- `vulnerability-validation` — produsen utama evidence hasil replay.
- `security-reporting` — konsumen evidence untuk report.
- `false-positive-analysis` — hasil FP check tersimpan sebagai evidence juga.
