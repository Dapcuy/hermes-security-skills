---
name: http-proxy-request-replay
description: >
  Use when a recorded request must be sent again under control: choosing safe
  methods first, honoring the request budget and approval scope, and stopping
  on any stop condition before, during, and after each replay.
version: 0.1.0
risk: medium
---

# HTTP Proxy Request Replay

## Purpose

- Metodologi replay request terekam dengan aman melalui capability replay: method aman dulu (idempotent sebelum stateful), budget tegas, dan stop condition aktif.
- Memastikan tiap replay punya alasan (hypothesis atau langkah validasi), approval yang sah, dan hasil yang tercatat.
- Menjadi fondasi teknis bagi skill domain — validasi, authz, IDOR — yang membutuhkan eksekusi request terkontrol.

## When To Use

- Skill validasi membutuhkan eksekusi request terkontrol terhadap target yang berada dalam scope.
- Baseline perlu di-refresh dengan request non-mutasi sebelum iterasi berikutnya.
- Konfirmasi ulang (reproduksi) temuan sebelum status dinaikkan.

## When Not To Use

- Authorization `pending` atau approval tidak ada — replay menunggu.
- Tanpa hypothesis atau tujuan eksplisit — replay "sekadar melihat" boros budget dan berisiko.
- Request yang akan memicu aksi destruktif, exfiltration, atau credential attack — kategoris dilarang (ROADMAP §2, §22).

## Authorization Preconditions

- Status `granted` atau `offline-lab`, dengan scope entry eksplisit untuk host/path yang direplay.
- Approval scoped aktif: capability, host, method, path, account reference bila authenticated, budget, dan expiry (ROADMAP §9).
- Scope direvalidasi lagi saat eksekusi di dalam proxy (TOCTOU guard, ROADMAP §4.2, §11) — approval tidak diasumsikan cukup sekali di awal.

## Required Context

- Request terekam yang akan direplay: method, path, header fungsional, dan body.
- Approval aktif dan sisa budget.
- Hypothesis atau tujuan replay.
- Account reference bila replay authenticated (ROADMAP §23).

## Required Capabilities

- `request_replay` — mengeksekusi replay melalui provider proxy, satu-satunya jalur traffic keluar (ROADMAP §5.2, §11).

Skill tidak menentukan provider maupun implementasi HTTP-nya; registry yang memilih (ROADMAP §4.1). Perbandingan pasca-replay diminta ke skill response comparison, bukan di sini.

## Core Concepts

- **Replay = request lama, konteks kini**: respons bisa berbeda karena waktu, data, atau state — perbedaan itu adalah data, bukan noise yang selalu diabaikan.
- **Aman dulu**: method idempotent (GET) sebelum stateful (POST/PUT/PATCH/DELETE); stateful menuntut approval risk HIGH (ROADMAP §8).
- **Budget dan ritme**: jumlah request, jeda antar request, dan konkurensi tunggal mengikuti execution plan yang disetujui (ROADMAP §9, §22).
- **Redirect no-follow**: default tidak mengikuti redirect; tiap redirect yang diikuti direvalidasi terhadap scope (ROADMAP §11).
- **Kegagalan itu jawaban**: replay yang ditolak policy adalah hasil sah, bukan rintangan untuk diakali.

## Reasoning Workflow

1. Pastikan hypothesis atau tujuan replay tertulis dan approval mencakup request yang akan dikirim.
2. Susun urutan: GET/idempotent lebih dulu; stateful hanya dengan approval HIGH dan mitigasi dampak.
3. Eksekusi satu replay per langkah; catat budget terpakai sebelum dan sesudah.
4. Tangani respons: status, redirect (no-follow default — catat lokasinya sebagai evidence bila terjadi), dan sinyal stop.
5. Serahkan perbandingan respons ke http-proxy-response-comparison; jangan menarik kesimpulan dari satu respons tanpa pembanding.
6. Ulangi hanya bila budget dan approval masih mencakup; berhenti tepat saat salah satu habis.

## Allowed Operations

- Replay GET di dalam budget approval, dengan jeda antar request sesuai rate limit (ROADMAP §22).
- Replay stateful hanya setelah approval HIGH dan mitigasi dampak tercatat (ROADMAP §8).
- Pengulangan replay reproduksi dalam budget yang sama, selama tidak ada stop condition terpicu.

## Approval Requirements

- Semua replay butuh approval scoped dengan budget dan expiry (ROADMAP §9); kadaluarsa berarti approval baru, bukan perpanjangan.
- Method stateful, upload, concurrency, dan transaction testing berstatus HIGH (ROADMAP §8).
- Pencabutan approval menghentikan replay yang berjalan — patuh penuh, tanpa "satu request terakhir" (ROADMAP §9).

## Forbidden Operations

- Replay di luar scope atau approval: host, path, method, atau account lain.
- Mengakali budget dengan menggabungkan beberapa operasi dalam satu request.
- Mengikuti redirect out-of-scope; respons dari origin out-of-scope tidak masuk reasoning (ROADMAP §11).
- Melanjutkan eksekusi setelah stop condition (ROADMAP §10) atau mengulang request yang ditolak policy dengan modifikasi tipis.

## Evidence Requirements

- Setiap replay tercatat: request id asal, waktu, budget terpakai, dan hasil status.
- Respons disimpan sebagai evidence ter-referensi (hash + path); body besar masuk reasoning sebagai ringkasan (ROADMAP §24).
- Redirect yang terjadi dicatat sebagai evidence, termasuk yang diblokir.

## False Positive Checks

- Respons sukses pada replay stateful bisa berarti efek samping terjadi — pastikan dampaknya dipahami, bukan hanya statusnya.
- Respons yang berbeda dari request asal bisa berasal dari perubahan waktu (expiry, rotasi), bukan perilaku keamanan.
- Halaman error generik bisa menyamarkan penolakan otorisasi — baca body sebelum mengklaim.

## Severity Guidance

- Replay tidak menetapkan severity; ia menghasilkan observation untuk skill validasi.
- Budget yang terpakai penuh tanpa hasil bermakna adalah hasil negatif yang sah — laporkan apa adanya, jangan dinaikkan jadi temuan.

## Stop Conditions

- Berhenti segera saat terpicu (ROADMAP §10): target out-of-scope, authorization expired, rate limit terdeteksi, repeated 5xx, latency naik signifikan, redirect out-of-scope, side effect tak terduga, respons berisi data sensitif, budget habis, policy berubah menjadi deny, atau approval dicabut.
- Setiap stop menghasilkan evidence entry dengan alasan; langkah berikutnya adalah laporan, bukan replay lanjutan.

## Output Format

- Replay record: hypothesis asal, request yang direplay, approval yang dipakai, budget terpakai, dan hasil per replay.
- Daftar stop condition yang terpicu (bila ada) beserta evidence-nya.
- Referensi evidence (hash + path) untuk tiap respons.

## Related Skills

- `http-proxy-request-mutation` — replay dengan satu variabel berubah.
- `http-proxy-response-comparison` — pembanding wajib hasil replay.
- `vulnerability-validation` — kontrak validasi yang memakai replay ini.
- `http-proxy-traffic-analysis` — sumber request terekam.
