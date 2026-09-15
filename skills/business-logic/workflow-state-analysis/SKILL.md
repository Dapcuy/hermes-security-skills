---
name: workflow-state-analysis
description: >
  Use when a multi-step workflow (checkout, onboarding, approval, password
  reset) can be modeled as a state machine and tested for skipped steps,
  reversed order, or restored state, using controlled replay with test
  accounts referenced by name only.
version: 0.1.0
risk: medium
requires_credentials: true
---

# Workflow State Analysis

## Purpose

- Memodelkan alur multi-langkah sebagai state machine dan mengujinya terhadap pelanggaran state: langkah dilewati, urutan dibalik, atau state di-restore.
- Membuktikan atau membantah hypothesis pelanggaran dengan replay terkontrol berbasis test account (ROADMAP §23, §26).
- Menjaga setiap mutasi state di dalam scope, budget, dan approval yang berlaku.

## When To Use

- Alur checkout, onboarding, approval, reset kredensial, atau verifikasi multi-langkah teridentifikasi dan model langkahnya jelas.
- Observation menunjukkan endpoint tahap akhir bisa diakses tanpa tahap awal, atau parameter state bisa diubah dari klien.
- Perlu dibuktikan bahwa urutan langkah memang ditegakkan (atau tidak) di server.

## When Not To Use

- Authorization `pending` atau scope tidak mencakup alur yang diuji (ROADMAP §8).
- Model alur belum ada — model dulu lewat business-logic-methodology sebelum mengeksekusi apa pun.
- Alur menyentuh transaksi finansial nyata — alihkan ke transaction-analysis dengan approval ketatnya.
- Pengujian membutuhkan mengulang aksi yang sama berkali-kali — pertimbangkan replay-and-duplicate-action-analysis.

## Authorization Preconditions

- Authorization `granted` atau `offline-lab` dengan scope entry eksplisit untuk host dan path tiap langkah alur.
- Approval aktif untuk replay stateful: method, path, budget, dan expiration sesuai §9 — langkah workflow umumnya POST/PUT sehingga ber-risk HIGH (ROADMAP §8).
- Test account per peran hanya dipakai melalui credential reference yang sah; jangan pernah menangani nilai kredensial langsung (ROADMAP §23).
- Alur yang memicu notifikasi atau aksi nyata ke pihak lain dihentikan atau dialihkan ke lab bila memungkinkan.

## Required Context

- Model state machine alur: langkah, urutan sah, state per langkah, dan identifier state (session, step token, field status).
- Baseline request/response per langkah pada jalur normal.
- Test account yang relevan beserta perannya, sebagai credential reference.
- Riwayat error dan validasi yang sudah terlihat di tiap langkah.

## Required Capabilities

- `request_replay` — mengeksekusi langkah alur dalam urutan yang dimodifikasi (dilewati, dibalik, atau diulang) terhadap target dalam scope.
- Skill hanya meminta replay; perbandingan hasil antar langkah dilakukan sebagai analisis atas data replay dan baseline.
- Provider replay ditentukan capability registry, dan replay aktif hanya berjalan di provider proxy (ROADMAP §4.1, §5.2).

## Required Credentials

- Pengujian berjalan pada alur authenticated dengan peran tertentu, sehingga frontmatter menyatakan `requires_credentials: true`.
- Hermes hanya melihat credential reference (mis. `account-a`, `account-b`), tidak pernah nilainya (ROADMAP §23).
- Control plane meng-inject kredensial saat eksekusi di dalam proxy; jangan pernah meminta nilai kredensial ditempel ke percakapan.
- Authorization kadaluarsa membuat credential reference terkait tidak lagi valid.

## Core Concepts

- **State machine sebagai model**: langkah, transisi sah, dan state akhir dituliskan dulu; pengujian adalah penyimpangan terkontrol dari model.
- **Tiga kelas pelanggaran**: skipped step (masuk ke tahap N tanpa tahap awal), reversed order (tahap akhir dieksekusi sebelum tahap awal), restored state (kembali ke tahap sebelumnya dan mengulang transisi yang sudah dilakukan).
- **Server-side enforcement**: pertanyaan intinya selalu "apakah server menegakkan urutan, atau hanya klien yang menegakkannya?"
- **Satu penyimpangan per percobaan**: ubah satu aspek state per iterasi agar hasil bisa diatribusikan.
- **State reset**: rencanakan kondisi awal yang bisa dipulihkan per iterasi tanpa merusak data orang lain.

## Reasoning Workflow

1. Tuliskan model alur: langkah, transisi, identifier state, dan state akhir; tetapkan prediksi pelanggaran mana yang mungkin.
2. Rekam baseline jalur normal per langkah dengan test account yang tepat.
3. Ajukan approval untuk replay stateful yang akan dijalankan, dengan budget per skenario penyimpangan.
4. Uji skipped step: eksekusi tahap akhir tanpa tahap awal; catat respons dan state akhir.
5. Uji reversed order: balik urutan dua langkah yang berdekatan; amati apakah server menerima.
6. Uji restored state: kembali ke tahap sebelumnya dan ulangi transisi; amati apakah state mundur atau ditolak.
7. Bandingkan hasil tiap penyimpangan dengan baseline; jalankan FP check, lalu perbarui status hypothesis (reproduced/inconclusive/rejected).

## Allowed Operations

- Replay langkah alur dengan satu penyimpangan state per iterasi, di dalam budget approval.
- Pengulangan langkah untuk mengembalikan kondisi awal yang terkendali, dihitung dalam budget.
- Analisis dan perbandingan state akhir antar iterasi.

## Approval Requirements

- Langkah workflow umumnya stateful (POST/PUT/PATCH) → risk HIGH → approval eksplisit wajib sebelum eksekusi (ROADMAP §8).
- Approval wajib scoped: capability, host, method, path, account reference, request budget, dan expiration (ROADMAP §9).
- Approval kadaluarsa dibuat ulang sebagai approval baru; pencabutan berarti menghentikan alur di state yang aman (ROADMAP §9, §10).

## Forbidden Operations

- Menjalankan penyimpangan state pada alur milik user lain tanpa test account yang sah.
- Membiarkan alur dalam state rusak tanpa mencatat dan (bila memungkinkan) mengembalikan kondisi awal.
- Mengubah banyak penyimpangan sekaligus sehingga penyebab tidak bisa diatribusikan.
- Melanjutkan eksekusi setelah stop condition terpicu atau side effect tidak terduga muncul (ROADMAP §10).

## Evidence Requirements

- Model state machine beserta sumbernya (spesifikasi atau traffic terekam).
- Per iterasi: skenario penyimpangan, request ter-sanitasi, respons, state akhir yang teramati, dan perbandingan dengan baseline.
- Kondisi awal dan akhir test account setelah rangkaian pengujian, sebagai bukti tidak ada kerusakan yang dibiarkan.
- Minimum set ROADMAP §25 untuk hypothesis yang naik status: reproduction steps, expected vs actual behavior, impact, FP analysis, dan sanitized artifact.

## False Positive Checks

- Apakah langkah yang "terlewati" sebenarnya opsional by design (mis. langkah opsional onboarding)?
- Apakah server menegakkan urutan lewat mekanisme lain yang tidak terlihat (signature step token, session state) sehingga percobaan gagal secara sah?
- Apakah "state di-restore" hanyalah idempotency langkah yang memang boleh diulang?
- Apakah respons sukses hanyalah echo parameter klien tanpa perubahan state server nyata?

## Severity Guidance

- Severity mengikuti dampak: langkah yang bisa dilewati menimbulkan dampak nyata (verifikasi tidak sah, hak diperoleh prematur) hanya bila state akhirnya berbahaya.
- Penyimpangan yang berhasil tetapi tanpa efek state bernilai rendah dan biasanya `inconclusive`, bukan finding berat.
- Alur kepercayaan (verifikasi identitas, approval berjenjang) yang bisa dilanggar cenderung severity tinggi bila terbukti.

## Stop Conditions

- Side effect tidak terduga (data user lain berubah, notifikasi keluar) → stop segera (ROADMAP §10).
- Budget habis sebelum skenario inti selesai → stop dan laporkan kondisi alur saat berhenti.
- Authorization kadaluarsa, approval dicabut, policy menjadi deny, atau target tidak sehat (repeated 5xx) → stop (ROADMAP §10).
- Alur membawa state test account ke kondisi yang tidak bisa dipulihkan → stop dan tandai untuk direset oleh pemilik engagement.

## Output Format

- Workflow state record: model alur, daftar skenario penyimpangan yang diuji, hasil per skenario, dan status hypothesis baru.
- State map akhir: kondisi test account setelah pengujian dan langkah pemulihan yang dilakukan.
- Referensi evidence (hash + path) untuk baseline dan tiap iterasi.

## Related Skills

- `business-logic-methodology` — peta routing hypothesis business logic.
- `transaction-analysis` — alur yang menyentuh transaksi finansial.
- `replay-and-duplicate-action-analysis` — pengulangan aksi dan idempotency.
- `vulnerability-validation` — kerangka validasi umum dan status lifecycle.
- `http-request-mutation` — manipulasi request lanjutan di domain proxy.
