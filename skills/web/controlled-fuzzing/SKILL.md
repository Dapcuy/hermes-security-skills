---
name: controlled-fuzzing
description: >
  Use when a single parameter must be exercised with a curated payload set
  under strict budget and rate discipline: one parameter per iteration, a
  small request total, one request per second, no concurrency, and automatic
  stops on rate limiting or repeated server errors.
version: 0.1.0
risk: medium
---

# Controlled Fuzzing

## Purpose

- Menjalankan input variation terkontrol terhadap satu parameter dengan disiplin budget dan rate yang ketat (ROADMAP §22).
- Mencegah unbounded fuzzing: total request kecil, satu request per detik, tanpa concurrency, dan stop otomatis pada sinyal beban.
- Menghasilkan observation per iterasi yang bisa dinilai satu per satu, bukan noise volumenya besar.

## When To Use

- Hypothesis mengindikasikan sebuah parameter menerima input tanpa validasi yang memadai dan perlu dibuktikan dengan iterasi kecil.
- Payload set bermetadata dari payload-selection sudah siap dan konteksnya cocok dengan parameter.
- Budget approval mencukupi jumlah iterasi yang direncanakan dan target dalam kondisi stabil.

## When Not To Use

- Authorization `pending`, kadaluarsa, atau scope tidak mencakup target (ROADMAP §8, §10).
- Tidak ada hypothesis — fuzzing tanpa hipotesis hanyalah generator noise dan pemborosan budget.
- Target menunjukkan rate limiting ketat, latensi tidak stabil, atau sedang dalam keadaan rapuh — pertimbangkan lab offline.
- Untuk credential attack, brute force login, atau menghabiskan kuota — itu dilarang total (ROADMAP §2, §22).

## Authorization Preconditions

- Authorization `granted` atau `offline-lab`, dengan scope entry eksplisit untuk host dan path yang diuji.
- Approval aktif yang menyatakan capability, method, path, request budget, dan expiration (ROADMAP §9).
- Total iterasi mengikuti budget dari approval — bukan dari selera skill; bila budget kurang, ajukan approval baru.
- Target yang menampilkan proteksi rate limit tetap boleh diuji hanya dalam batas budget yang sama, tanpa pengecualian.

## Required Context

- Parameter tunggal yang diuji: lokasi, tipe, dan konteks parsing.
- Baseline response yang bersih untuk request yang sama tanpa mutasi.
- Payload set terkurasi dengan metadata lengkap dari payload-selection.
- Riwayat 429/5xx sebelumnya pada target dan sisa request budget saat ini.

## Required Capabilities

- `request_replay` — mengeksekusi satu request mutasi per iterasi terhadap target yang berada dalam scope.
- Skill hanya meminta capability; eksekusi berjalan di provider proxy sesuai registry (ROADMAP §4.1, §5.2).
- Perbandingan respons hasil iterasi dilakukan sebagai analisis atas data replay, bukan sebagai capability terpisah di sini.

## Core Concepts

- **Satu parameter per iterasi**: hanya satu variabel berubah per request agar perbedaan respons bermakna dan bisa diatribusikan.
- **Angka keras ROADMAP §22**: total request maksimum 50 per task, rate 1 request per detik, concurrency maksimum 1.
- **stop_on_429 dan stop_on_repeated_5xx**: respons tersebut menghentikan run — tidak ada retry otomatis (ROADMAP §22, §10).
- **Budget dari approval**: jumlah request disetujui di approval, dan skill tidak menambah sendiri.
- **Observation, bukan verdict**: setiap iterasi menghasilkan observation terstruktur; payload sukses bukan konfirmasi vulnerability.

## Reasoning Workflow

1. Kunci parameter tunggal, hypothesis yang diuji, dan prediksi perubahan respons untuk iterasi ini.
2. Pastikan baseline response dan payload set siap; urutkan payload dari yang paling tidak invasif.
3. Konfirmasi approval: budget, method, path, dan expiry masih aktif untuk seluruh iterasi yang direncanakan.
4. Eksekusi iterasi: satu payload, satu request, jeda sesuai rate limit; catat respons per iterasi.
5. Evaluasi setiap respons terhadap prediksi; berhenti segera bila stop condition terpicu.
6. Setelah budget habis atau prediksi terjawab, ringkas observation dan serahkan ke false-positive check serta validasi lanjutan.

## Allowed Operations

- Replay terhadap method dan path yang disetujui, dengan rate 1 request/detik, concurrency 1, dan total di dalam budget.
- Menghentikan run lebih awal kapan pun respons tidak lagi informatif.
- Mengulang baseline (bukan payload) untuk memastikan respons pembanding masih valid, dihitung dalam budget.

## Approval Requirements

- Replay ber-risk MEDIUM → approval conditional; bila iterasi menyentuh method stateful (POST/PUT/PATCH/DELETE), risk menjadi HIGH → approval eksplisit wajib sebelum eksekusi (ROADMAP §8).
- Approval wajib scoped: capability, host, method, path, request budget, dan expiration (ROADMAP §9).
- Approval kadaluarsa dibuat ulang sebagai approval baru; tidak ada perpanjangan diam-diam, dan pencabutan berarti berhenti segera (ROADMAP §9, §10).

## Forbidden Operations

- Melebihi 50 request per task, 1 request/detik, atau concurrency di atas 1 tanpa approval yang secara eksplisit menyatakan angka tersebut.
- Retry otomatis saat menerima 429 atau repeated 5xx.
- Memutasi beberapa parameter sekaligus dalam satu iterasi.
- Payload destructive, exfiltration, atau credential attack list (ROADMAP §22).
- Melanjutkan eksekusi setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Per iterasi: payload id, waktu, status code, ringkasan respons, dan hasil perbandingan dengan baseline.
- Rekap budget terpakai versus budget yang disetujui.
- Stop reason bila run berhenti lebih awal, beserta iterasi terakhir yang dijalankan.

## False Positive Checks

- Apakah perubahan respons berasal dari cache atau WAF challenge, bukan dari efek payload di server?
- Apakah respons "error" sebenarnya rate-limit page yang bentuknya menyerupai bug?
- Apakah observation flaky — ulang baseline dan bandingkan sebelum menganggapnya signal.
- Apakah payload memicu perbedaan yang trivial (mis. panjang respons) tanpa makna fungsional?

## Severity Guidance

- Fuzzing tidak menetapkan severity; severity ditetapkan dari dampak vulnerability yang tervalidasi, bukan dari jumlah iterasi.
- Iterasi tanpa hasil bukan bukti keamanan — bisa berarti hypothesis salah; perbarui status menjadi `rejected` atau `inconclusive`, bukan "aman".
- Bila meyakinkan diri butuh volume makin besar, itu tanda kembali ke hypothesis dan memperbaiki prediksi, bukan menambah budget.

## Stop Conditions

- 429 diterima → stop segera, catat stop reason (ROADMAP §10, §22).
- Repeated 5xx → stop segera; target kemungkinan tidak sehat.
- Request budget habis → stop, rangkum apa yang sudah terobservasi.
- Latensi naik signifikan, redirect out-of-scope, side effect tidak terduga, atau respons berisi data sensitif → stop segera (ROADMAP §10).

## Output Format

- Fuzzing run record: parameter, hypothesis id, daftar iterasi (payload, status, ringkasan), budget terpakai, stop reason, dan referensi evidence.
- Ringkasan observation yang menonjol beserta rekomendasi: lanjut validasi, perbaiki hypothesis, atau berhenti.
- Status akhir run: prediksi terjawab, tidak conclusif, atau dihentikan lebih awal — disertai alasannya.

## Related Skills

- `payload-selection` — penyusun payload set bermetadata sebelum run.
- `injection-validation` — validasi indikasi injection yang muncul dari iterasi.
- `vulnerability-validation` — kerangka validasi umum dan status lifecycle.
- `false-positive-analysis` — penyisiran observation mencurigakan.
- `http-request-replay` — skill domain operasi replay lanjutan.
