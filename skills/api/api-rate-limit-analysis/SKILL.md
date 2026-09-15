---
name: api-rate-limit-analysis
description: >
  Use when assessing abuse controls on data or authentication endpoints:
  identifying throttling signals from responses, measuring thresholds with
  low-volume binary search inside an explicit request budget, and separating
  application limits from infrastructure limits.
version: 0.1.0
risk: medium
---

# API Rate Limit Analysis

## Purpose

- Menilai kontrol abuse: throttling, quota, dan ketahanan terhadap pengulangan pada endpoint yang menyediakan data atau autentikasi.
- Mengukur threshold dengan volume rendah dan batas aman — pencarian biner atas respons yang teramati, bukan brute force penuh.
- Memisahkan limit yang hidup di aplikasi dari limit di CDN/load balancer, karena lokasi limit menentukan makna temuan dan perbaikannya.

## When To Use

- Endpoint sensitif teridentifikasi (login, OTP, reset, pencarian, ekspor) dan ketahanannya terhadap pengulangan perlu diketahui.
- Sinyal 429 atau header pembatasan terlihat di history dan perilakunya perlu dipahami lebih dalam.
- Pagination besar atau endpoint agregasi menimbulkan dugaan pengambilan data massal dengan request sedikit.

## When Not To Use

- Program terms melarang pengujian rate limit — hormati dan catat sebagai gap cakupan.
- Target sedang tidak stabil atau sudah menunjukkan 5xx — pengujian ini menambah beban.
- Tujuannya credential attack (stuffing, cracking) — dilarang mutlak di seluruh project (ROADMAP §2, §22).

## Authorization Preconditions

- Approval WAJIB sebelum replay pertama; budget (jumlah, laju, jeda) tertulis di approval, bukan diputuskan saat runtime (ROADMAP §8, §9, §22).
- Status `granted` atau `offline-lab`; rate limit produksi adalah kontrol keamanan yang diuji dengan persetujuan, bukan dilanggar.
- Akun uji khusus (credential reference) bila limit diperkirakan per-user; jangan memakai akun produksi nyata (ROADMAP §23).

## Required Context

- Sinyal pasif dari history yang sudah dianalisis skill traffic analysis: pola 429, header pembatasan, perubahan respons setelah lonjakan.
- Daftar endpoint kandidat dan nilai datanya (login versus pencarian publik) sebagai urutan prioritas.
- Program terms: batas laju yang diizinkan program dan larangan khusus terkait pengujian beban.
- Budget yang disetujui: jumlah request maksimum, laju rendah, jeda antar request, dan aturan berhenti.

## Required Capabilities

- `request_replay` — mengulang request terkontrol di dalam budget approval untuk membaca perilaku pembatasan.
- Perbandingan dan penghitungan threshold dilakukan atas hasil replay yang tersimpan; capability analisis tambahan tidak diperlukan.
- Skill tidak menentukan provider; replay hanya dijalankan provider proxy yang punya privilege egress (ROADMAP §4.1, §5.2, §11).

## Core Concepts

- **Sinyal pembatasan**: status 429, header quota/retry, peningkatan latensi, dan respons yang berubah bentuk setelah sejumlah request.
- **Pencarian biner threshold**: mulai dari jumlah kecil, gandakan atau pecah berdasarkan hasil — menemukan titik batas dengan log(n) iterasi, bukan ratusan request.
- **Burst allowance**: banyak implementasi mengizinkan lonjakan pendek sebelum menghukum — angka pertama yang terlihat bukan threshold efektif.
- **Per-user versus per-IP**: limit yang terikat akun terlihat dari perbedaan respons antar akun; yang terikat IP terlihat tanpa autentikasi — dua temuan berbeda.
- **Pagination abuse**: page size besar atau kedalaman halaman bebas memungkinkan ekspor dataset dengan request sedikit — kelemahan abuse tanpa melampaui limit.
- **Friksi brute-force**: endpoint autentikasi yang tidak menaikkan friksi (lockout, captcha, delay) setelah kegagalan berulang adalah temuan — diuji dengan hitungan kecil pada akun uji sendiri.

## Reasoning Workflow

1. Kumpulkan sinyal pasif dari catatan history di case memory (hasil skill analisis traffic) — tanpa mengirim request.
2. Rumuskan hipotesis limit per endpoint: per-user, per-IP, per-endpoint, atau global, beserta sinyal pendukungnya.
3. Ajukan approval dengan budget eksplisit: jumlah request, laju rendah, jeda, dan aturan berhenti (ROADMAP §9, §22).
4. Jalankan seri pendek berjarak: amati respons tiap request; berhenti segera pada 429 pertama.
5. Persempit threshold dengan pencarian biner atas titik yang sudah teramati; setiap iterasi dikurangi dari budget yang tersisa.
6. Bedakan lokasi limit: bandingkan perilaku sebelum dan sesudah autentikasi; perhatikan indikator infrastruktur pada header.
7. Uji pagination abuse secara kualitatif: satu request page size besar pada data milik akun uji sendiri, bandingkan ukuran dan isi respons.
8. Catat kesimpulan: threshold teramati, sinyal, lokasi limit, dan friksi brute-force — masing-masing dengan referensi replay id.

## Allowed Operations

- Seri replay berjarak dengan laju rendah di dalam budget approval; maksimal satu request dalam penerbangan.
- Pencarian biner threshold dengan total request tetap kecil (puluhan, bukan ratusan).
- Satu request pagination besar terhadap data milik akun uji sendiri.

## Approval Requirements

- Budget, laju, dan aturan berhenti wajib tertulis di approval sebelum replay pertama — konsisten dengan guardrail payload: rate limit rendah, stop saat 429, stop saat repeated 5xx (ROADMAP §9, §22).
- Pengujian endpoint autentikasi dengan kegagalan berulang butuh persetujuan eksplisit pemilik target dan akun uji khusus.
- Tidak ada perpanjangan diam-diam; pengujian lanjutan memakai approval baru (ROADMAP §9).

## Forbidden Operations

- Brute force penuh: menghabiskan ratusan hingga ribuan request untuk memetakan limit dengan pasti.
- Credential attack dalam bentuk apa pun — dilarang mutlak (ROADMAP §2, §22).
- Melanjutkan pengiriman setelah 429 — aturan berhenti saat 429 tidak bisa dinegosiasikan (ROADMAP §10, §22).
- Menargetkan endpoint tanpa baseline atau di luar scope entry yang sah.

## Evidence Requirements

- Tabel percobaan: urutan, waktu, jumlah, dan respons — dengan referensi replay id per baris.
- Threshold teramati beserta sinyal pendukung (status, header, perubahan bentuk respons).
- Analisis lokasi limit: aplikasi versus infrastruktur, beserta indikatornya.
- Rekonsiliasi budget: request terpakai versus yang disetujui.

## False Positive Checks

- Limit di CDN atau load balancer bukan limit aplikasi — temuan tetap sah tetapi lokasi perbaikannya berbeda.
- Burst allowance membuat threshold tampak lebih tinggi pada seri pertama; ukur ulang setelah jeda.
- 429 dari upstream pihak ketiga (bukan target) bukan bukti kontrol milik target.
- Respons yang berubah bisa karena cache atau eviction, bukan pembatasan.

## Severity Guidance

- Endpoint autentikasi tanpa friksi terhadap pengulangan: tinggi (jalur akses akun).
- Ekspor massal via pagination pada data sensitif: tinggi; pada data publik: rendah.
- Limit longgar pada endpoint data non-sensitif: rendah.
- Severity mengikuti dampak abuse yang terbukti, bukan sekadar tidak adanya limit.

## Stop Conditions

- 429 pertama → berhenti segera (ROADMAP §10, §22).
- Latensi meningkat signifikan atau repeated 5xx → berhenti (ROADMAP §10).
- Budget approval terpakai habis → berhenti; kelanjutan lewat approval baru.
- Akun uji terkunci atau suspended → berhenti dan laporkan.

## Output Format

- Laporan threshold per endpoint: hipotesis limit, angka teramati, sinyal, dan tingkat keyakinan.
- Analisis lokasi limit dan friksi brute-force per endpoint.
- Rekonsiliasi budget: total request terpakai dan sisa.

## Related Skills

- `api-security-methodology` — konteks prioritas endpoint.
- `http-request-replay` — mekanisme replay yang dipakai lewat capability.
- `replay-and-duplicate-action-analysis` — pengulangan aksi stateful (fokus bisnis, bukan volume).
- `jwt-and-token-analysis` — friksi pada endpoint refresh/OTP sering berpasangan.
- `false-positive-analysis` — triase temuan abuse control.
