---
name: http-response-comparison
description: >
  Use when comparing a baseline response against an actual response: diffing
  status, headers, and body, classifying each difference pattern, and knowing
  which patterns carry security meaning versus cosmetic noise.
version: 0.1.0
risk: low
---

# HTTP Response Comparison

## Purpose

- Membandingkan respons baseline dengan respons aktual: diff status, header, dan body, lalu mengklasifikasikan makna tiap pola.
- Memberi diskriminan bagi validasi: memisahkan perbedaan yang relevan dengan hypothesis dari noise kosmetik.
- Read-only: capability comparison bekerja atas data yang sudah ada (baseline dan hasil replay) tanpa mengirim traffic baru.

## When To Use

- Setelah replay atau mutasi, untuk menilai apakah respons berubah dan bagaimana bentuknya.
- Saat validasi menuntut bukti perbandingan (expected versus actual) sebagai bagian evidence (ROADMAP §25).
- Triase anomali dari traffic analysis: bandingkan respons anomali dengan baseline.

## When Not To Use

- Baseline tidak ada atau tidak setara kondisinya (akun, path, atau waktu yang berbeda) — perbandingan menyesatkan.
- Sebagai pengganti validasi: diff adalah sinyal, bukan kesimpulan vulnerability.
- Body yang membawa data sensitif perlu redaksi terlebih dulu sebelum masuk konteks (ROADMAP §23, §24).

## Authorization Preconditions

- Comparison read-only dan tidak mengirim traffic; datanya berasal dari jalur yang sah — history atau replay ber-approval.
- Data yang dibandingkan wajib berasal dari operasi dalam scope; hasil out-of-scope tidak dibandingkan, hanya dicatat sebagai evidence blokir (ROADMAP §11).
- Sanitasi kredensial berlaku sebelum body masuk konteks (ROADMAP §23).

## Required Context

- Respons baseline dan respons aktual yang akan dibandingkan, beserta konteksnya: request asal, akun (reference), dan waktu.
- Hypothesis yang sedang diuji agar klasifikasi diff relevan.
- Daftar bagian dinamis respons (nonce, timestamp, id sesi) dari traffic analysis.

## Required Capabilities

- `response_comparison` — menjalankan perbandingan terstruktur atas pasangan respons.

- `json_diff` — perbandingan body JSON terstruktur; berjalan di provider lokal tanpa jaringan (ROADMAP §5.3).

Skill tidak menentukan provider (ROADMAP §4.1).

## Core Concepts

- **Tiga lapis diff**: status code, header, body — baca berurutan, karena status sering menjelaskan sisanya.
- **Pola bermakna**: 403 menjadi 200 pada identitas berbeda (sinyal authorization); 404 menjadi 200 pada path tertentu (sinyal keberadaan endpoint); body bertambah field data (sinyal kebocoran).
- **Pola kosmetik**: perubahan panjang kecil dari timestamp/nonce, urutan field JSON, compression, dan banner cache — tidak bermakna keamanan.
- **Tidak ada diff pun informasi**: respons identik antara identitas berbeda adalah indikasi otorisasi yang tidak membedakan object — atau cache; pisahkan keduanya.

## Reasoning Workflow

1. Pastikan pasangan pembanding setara: request yang sama (kecuali variabel yang diuji) dan kondisi akun yang jelas.
2. Jalankan `response_comparison` atas pasangan baseline/actual; pakai `json_diff` untuk body JSON yang besar.
3. Baca diff berlapis: status lebih dulu, lalu header bermakna (location, cookie fungsional, ukuran sebagai petunjuk), lalu body.
4. Klasifikasikan tiap perbedaan: substantif (relevan dengan hypothesis), kosmetik (dinamis/kompresi), atau tidak diketahui (butuh iterasi lanjutan).
5. Tafsirkan pola terhadap hypothesis — contoh: identitas berbeda tetapi body identik menunjuk otorisasi yang tidak membedakan object.
6. Simpan klasifikasi sebagai bagian evidence validasi, termasuk diff yang ternyata noise agar iterasi berikutnya tidak mengulang salah baca.

## Allowed Operations

- Perbandingan atas pasangan respons yang diperoleh lewat jalur sah — tanpa batas jumlah perbandingan, karena nol traffic.
- Klasifikasi dan dokumentasi pola diff di case memory.
- Rekomendasi iterasi lanjutan (mutasi/replay) bila diff tidak conclusive — tanpa mengeksekusinya.

## Approval Requirements

- Tidak ada approval — comparison tidak mengirim traffic.
- Iterasi lanjutan hasil rekomendasi butuh approval sendiri di skill eksekusi (ROADMAP §8, §9).

## Forbidden Operations

- Mengirim request tambahan "untuk melengkapi perbandingan".
- Mengklaim `confirmed` atau `reproduced` dari pola diff saja — konfirmasi lewat kontrak vulnerability-validation (ROADMAP §26).
- Memasukkan body berisi kredensial atau data sensitif ke konteks tanpa redaksi (ROADMAP §23, §24).

## Evidence Requirements

- Pasangan pembanding ter-referensi: request id, waktu, akun (reference), dan sumber (history/replay).
- Klasifikasi diff per lapis dengan alasan tiap keputusan.
- Kutipan body cukup untuk membuktikan klaim, ter-redact dari data sensitif (ROADMAP §23, §25).

## False Positive Checks

- Diff kosmetik dari content dinamis (timestamp, nonce, id sesi) — cek daftar field dinamis dari baseline.
- Cache menyajikan respons identik antar kondisi berbeda — verifikasi header cache.
- Compression dan encoding membuat body tampak berbeda padahal setara.
- Diff yang "identik" bisa berarti proxy mengembalikan halaman error generik untuk kedua sisi.

## Severity Guidance

- Skill ini tidak menetapkan severity; ia memasok diskriminan.
- Makna pola diff (mis. 403 menjadi 200) menunjukkan arah hypothesis, bukan angka severity; severity ditetapkan setelah dampak terbukti.

## Stop Conditions

- Pasangan pembanding tidak setara (akun/path/waktu yang tak bisa disetarakan) → nyatakan perbandingan tidak sah, jangan paksa kesimpulan.
- Diff menunjukkan data sensitif tak terduga → berhenti, redact, laporkan (ROADMAP §10).
- Sumber data ternyata dari operasi out-of-scope → hentikan penggunaan data itu.

## Output Format

- Comparison record: pasangan respons, hasil diff per lapis (status/header/body), dan klasifikasinya.
- Interpretasi terhadap hypothesis: didukung, terbantahkan, atau inconclusive.
- Referensi evidence (hash + path) untuk kedua sisi perbandingan.

## Related Skills

- `vulnerability-validation` — kontrak validasi yang memakai comparison ini.
- `http-request-replay`, `http-request-mutation` — pemasok respons aktual.
- `http-traffic-analysis` — pemasok baseline dan daftar bagian dinamis.
- `false-positive-analysis` — triase lanjutan atas sinyal.
