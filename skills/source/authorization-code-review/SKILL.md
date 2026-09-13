---
name: authorization-code-review
description: >
  Use when authorization implementation in source code needs review:
  missing object-level or function-level checks, IDOR-prone patterns,
  and role checks placed in the wrong layer.
version: 0.1.0
risk: low
---

# Authorization Code Review

## Purpose

- Meninjau implementasi authorization di kode: check yang hilang, salah letak, atau salah skop.
- Mengidentifikasi pola rawan IDOR: objek diambil berdasarkan identifier dari input tanpa verifikasi kepemilikan.
- Mengidentifikasi pola rawan BFLA: fungsi sensitive yang tidak ter-gate role di layer server.
- Menghasilkan hipotesis berbasis kode yang bisa dibuktikan lewat pengujian dinamis (ROADMAP §26), bukan klaim final.

## When To Use

- Triage menandai auth boundary sebagai prioritas review.
- Temuan dinamis (mis. dari web-authorization atau idor-and-bola) butuh penjelasan akar masalah di kode.
- User meminta penilaian kualitas kontrol akses sebelum rilis.
- Codebase baru dan model role/permission perlu dipahami sebelum pengujian.

## When Not To Use

- Tidak ada akses ke kode — gunakan pengujian dinamis lewat web-authorization.
- Sebagai pengganti verifikasi perilaku runtime: kode yang direview bisa berbeda dari yang ter-deploy.
- Untuk isu autentikasi (verifikasi identitas) — fokus skill ini adalah authorization: keputusan akses setelah identitas diketahui.

## Authorization Preconditions

- Analisis pasif atas kode yang sah diserahkan; tidak ada request ke target dari skill ini (ROADMAP §8).
- Hipotesis yang butuh pembuktian dinamis dieksekusi lewat skill validasi dengan authorization dan approval sendiri (ROADMAP §8, §9).
- Bila review melibatkan skenario multi-akun, akun uji hanya dirujuk sebagai reference, bukan nilainya (ROADMAP §23).

## Required Context

- Review map dari source-code-triage atau daftar file auth-critical yang setara.
- Mekanisme authorization framework yang dipakai: middleware, decorator, policy object, annotation.
- Model peran/permission aplikasi: role apa saja, resource apa yang dilindungi.
- Contoh route/handler representatif per kelompok akses (publik, user, admin).

## Required Capabilities

Tidak ada capability aktif yang diperlukan. Review murni analisis file lokal: membaca kode, melacak pola, dan mendokumentasikan temuan sebagai hipotesis (ROADMAP §4.1, §8).

## Core Concepts

- **Object-level check**: verifikasi bahwa objek yang diakses benar milik peminta; absennya check ini adalah pola IDOR-prone.
- **Function-level check**: verifikasi role boleh memanggil fungsi/endpoint; absennya adalah pola BFLA-prone.
- **Lokasi check**: check terpusat (middleware/policy) vs tersebar per-handler yang mudah terlewat satu per satu.
- **Deny-by-default**: route baru yang lupa diberi gate harus ditolak; perilaku allow-by-default adalah temuan tersendiri.
- **Identifier dari input**: ID/UUID/slug yang berasal dari request dan langsung dipakai query tanpa filter kepemilikan.
- **Trust antar service**: panggilan internal yang menganggap request sudah terotorisasi — trust boundary yang sering salah asumsi.

## Reasoning Workflow

1. Petakan mekanisme authorization: di mana keputusan akses diambil dan bagaimana diterapkan.
2. Untuk tiap endpoint sensitive, telusuri: bagaimana objek diambil, dari mana identifier berasal, apakah ada verifikasi kepemilikan.
3. Periksa penegakan role: terpusat atau per-handler; catat endpoint yang lolos tanpa gate.
4. Bandingkan endpoint sejenis: perbedaan perlakuan antar handler sering menunjukkan check yang terlewat.
5. Klasifikasikan pola (missing object-level, missing function-level, check di layer salah) dan beri referensi file + baris.
6. Rumuskan hipotesis pengujian dinamis yang membuktikan atau membantah pola tersebut.

## Allowed Operations

- Membaca dan menganotasi kode; menandai lokasi check yang hilang atau salah letak.
- Menyusun tabel pola authorization per endpoint dengan status hipotesis.
- Merekomendasikan skenario validasi dinamis (endpoint, akun reference, hasil yang diharapkan).

## Approval Requirements

- Tidak ada approval: seluruh operasi pasif (ROADMAP §8).
- Skenario validasi yang disarankan tidak dieksekusi dari skill ini — jalankan lewat skill validasi dengan approval tersendiri (ROADMAP §9).
- Rekomendasi yang melibatkan method state-changing disertai catatan bahwa approval HIGH akan diperlukan saat eksekusi (ROADMAP §8).

## Forbidden Operations

- Menyatakan temuan `confirmed` hanya dari kode tanpa pembuktian perilaku (ROADMAP §26).
- Membuktikan hipotesis dengan mengakses data user lain langsung dari skill ini.
- Memodifikasi kode, branch, atau konfigurasi repo.
- Mengeksekusi kode atau test dari repo demi "mencoba" pola authorization.

## Evidence Requirements

- Tiap temuan: file + baris, pola yang terdeteksi, check yang hilang, dan skenario penyalahgunaan yang mungkin.
- Klasifikasi status: `suspected` sampai terbukti dinamis (ROADMAP §26).
- Skenario validasi yang direkomendasikan lengkap dengan preconditions dan hasil yang diharapkan.
- Provenance versi kode yang direview agar temuan bisa direproduksi.

## False Positive Checks

- Check kepemilikan bisa berada di decorator/middleware/repository yang tidak terlihat di handler — telusuri sebelum menyimpulkan hilang.
- Framework atau ORM bisa menyaring otomatis berdasarkan scope user (default scope, plugin multi-tenant).
- Identifier dari session/token bukan dari input bebas — risikonya berbeda.
- Resource yang memang publik-by-design bukan IDOR meski ID-nya berturutan.
- Endpoint internal yang hanya dicapai setelah gate lain — periksa keterjangkauan nyatanya.

## Severity Guidance

- Severity hipotesis dihitung dari dampak terburuk bila pola benar: akses lintas akun massal → tinggi; akses fungsi admin → tinggi; kebocoran terbatas → sedang.
- Status tetap `suspected`; severity final menunggu validasi (ROADMAP §26).
- Deny-by-default yang bolong satu endpoint dinilai dari data yang terekspos di endpoint itu, bukan dari jumlah celahnya saja.

## Stop Conditions

- Kode yang tersedia tidak memuat layer authorization (ditangani service eksternal yang tidak diserahkan) → catat keterbatasan, minta kode tersebut.
- Dua jalur analisis menghasilkan kesimpulan bertentangan dan tidak bisa didamaikan → berhenti dan tanyakan ke user.
- Pola ditemukan tapi keterjangkauan runtime tidak bisa dinilai dari kode → tandai perlu validasi, jangan memaksa kesimpulan.

## Output Format

- Tabel temuan: lokasi (file:baris), pola, kontrol yang hilang, dampak potensial, status lifecycle.
- Ringkasan arsitektur authorization: di mana check diterapkan, seberapa konsisten, dan area paling rapuh.
- Daftar rekomendasi validasi dinamis terurut prioritas.

## Related Skills

- `source-code-triage` — penyedia review map area auth.
- `web-authorization` dan `idor-and-bola` — pembuktian dinamis pola object-level.
- `bfla` — pembuktian dinamis pola function-level.
- `server-side-data-flow` — melengkapi analisis dengan jejak data ke sink.
- `vulnerability-validation` — eksekusi validasi hipotesis.
- `false-positive-analysis` — menimbang temuan yang ambigu.
