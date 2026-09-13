---
name: graphql-security
description: >
  Use when a GraphQL endpoint is in scope: schema exposure, resolver-level
  authorization, query depth and batching behavior with minimal payloads,
  alias abuse, mutation authorization, and GraphQL-specific error disclosure.
version: 0.1.0
risk: medium
---

# GraphQL Security

## Purpose

- Menilai keamanan endpoint GraphQL: eksposur schema, otorisasi per resolver, dan kontrol resource terhadap query yang menggerus batas komputasi.
- Menguji dengan query KECIL: bukti perilaku (diterima, ditolak, atau dibatasi) dicapai dengan jumlah query sedikit — bukan stress atau resource exhaustion sungguhan.
- Menegaskan perbedaan model GraphQL: satu endpoint, banyak resolver — otorisasi pada level endpoint tidak menjamin otorisasi tiap field.

## When To Use

- Endpoint GraphQL teridentifikasi dari surface mapping dan berada dalam scope.
- Introspection terbuka atau schema tersedia dan perlu dipetakan menjadi permukaan uji.
- History menunjukkan query bersarang dalam, alias ganda, atau pengiriman batch yang mengindikasikan kontrol perlu diverifikasi.

## When Not To Use

- Endpoint REST → `rest-api-testing`; endpoint GraphQL di luar scope → jangan disentuh sama sekali.
- Tujuannya mengukur ketahanan beban nyata — skill ini hanya membuktikan ada atau tidaknya limit.
- Authorization `pending` atau approval replay belum ada (ROADMAP §8, §9).

## Authorization Preconditions

- Status `granted` atau `offline-lab`; approval scoped untuk query yang diuji per endpoint (ROADMAP §8, §9).
- Mutation uji hanya pada data milik akun uji dan disetujui eksplisit dengan risk HIGH (ROADMAP §8).
- Pengujian depth/batching dinyatakan di approval sebagai pembuktian perilaku dengan jumlah query kecil, bukan pengujian beban.

## Required Context

- Endpoint dan header autentikasi dari history; schema bila introspection terbuka atau file schema tersedia.
- Baseline respons: bentuk error GraphQL standar, status code, dan struktur data normal.
- Akun uji (reference, ROADMAP §23) dan peran yang tersedia untuk uji resolver lintas peran.
- Program terms: larangan khusus GraphQL (beberapa program membatasi introspection testing).

## Required Capabilities

- `request_replay` — mengirim query uji kecil di dalam approval aktif.
- `response_comparison` — membandingkan respons antar query dan antar akun untuk menilai otorisasi resolver.
- `openapi_analysis` — bila schema diekspor atau terdokumentasi, menganalisis struktur type dan field sebagai peta uji.

Skill tidak menentukan provider; replay aktif hanya berjalan melalui provider proxy yang punya privilege egress (ROADMAP §4.1, §5.2, §11).

## Core Concepts

- **Introspection**: schema yang bisa dibaca mempercepat pemetaan; terbuka bukan otomatis temuan — nilainya kontekstual (endpoint internal versus publik).
- **Resolver-level authorization**: tiap field adalah pintu; endpoint yang mengenali pengguna tidak berarti tiap resolver memeriksa otorisasi.
- **Depth dan alias**: query bersarang dalam atau alias ganda menguji batas komputasi — perilaku yang dicari adalah adanya penolakan, bukan keberhasilan menghabiskan resource.
- **Batching**: banyak query dalam satu request (array atau alias) bisa melewati limit per-request; bukti cukup dengan beberapa query saja.
- **Error disclosure**: stack trace, pesan internal library, dan echo variabel pada error GraphQL membocorkan struktur backend.
- **Mutation tanpa authz**: mutasi yang tereksekusi tanpa pemeriksaan otorisasi field-level adalah kategori temuan tertinggi di sini.

## Reasoning Workflow

1. Konfirmasi endpoint dan baseline: satu query sederhana; catat bentuk respons dan error standar.
2. Bila introspection terbuka, petakan type dan field sensitif (field administratif, relasi lintas pengguna); bila tertutup, gunakan history dan schema yang tersedia.
3. Pilih dua-tiga resolver sensitif; uji otorisasi: query field terproteksi dengan akun berperan rendah, bandingkan dengan baseline akun berperan tinggi.
4. Uji kontrol resource dengan query KECIL: satu query sedikit lebih dalam dari wajar dan satu alias/batch ganda — cukup untuk melihat ada atau tidaknya limit.
5. Amati error disclosure: kirim satu query tidak valid sederhana dan periksa apakah stack trace atau detail internal muncul.
6. Untuk mutation, mulai dari mutasi aman pada data milik akun uji; mutasi lintas akun rutenya `idor-and-bola`.
7. Simpan seluruh hasil sebagai observation dengan referensi replay id; severity lahir setelah validasi (ROADMAP §26).

## Allowed Operations

- Query kecil (kedalaman satu digit) di dalam budget per endpoint.
- Satu-dua query depth atau batching di atas ambang wajar semata untuk mengamati penolakan.
- Query tidak valid sederhana untuk membaca perilaku error.

## Approval Requirements

- Approval scoped per endpoint; budget kecil tertulis sebelum replay pertama (ROADMAP §9).
- Mutation uji butuh approval eksplisit dengan dampak data yang dinyatakan (risk HIGH, ROADMAP §8).
- Pengujian depth/batching dinyatakan di approval sebagai pembuktian perilaku, termasuk jumlah query maksimum.

## Forbidden Operations

- Mengirim query exhaust sungguhan (ratusan alias atau kedalaman ratusan) — bukti perilaku cukup dari satu-dua query.
- Mengulang batch besar untuk "memastikan" — satu pengamatan penolakan atau keberhasilan cukup.
- Mengeksekusi mutation administratif atau destruktif dalam bentuk apa pun.
- Menyimpulkan kelemahan hanya karena introspection terbuka.

## Evidence Requirements

- Pasangan baseline-versus-query uji dengan referensi replay id.
- Hasil uji otorisasi resolver: query, akun reference, respons, dan kesimpulan sementara per resolver.
- Rekaman perilaku limit: penolakan, truncation, atau tidak ada limit — dengan jumlah query yang terpakai.
- Kutipan error ter-redact sebagai bukti disclosure, bukan dump penuh (ROADMAP §25).

## False Positive Checks

- Introspection terbuka pada endpoint internal atau dokumentasi bisa disengaja — konteks penyebaran menentukan.
- Depth limit yang sudah ada menolak query uji — itu kontrol bekerja, bukan temuan.
- Error yang memuat nama field bisa berupa pesan validasi yang dirancang; bedakan dari stack trace mentah.
- Persisted query atau automatic persisting membuat variasi query tidak berjalan — perilaku berbeda, bukan kelemahan.

## Severity Guidance

- Mutation lintas akun tanpa otorisasi: tinggi (setelah divalidasi skill rute).
- Resolver data sensitif terbaca lintas peran: tinggi.
- Error disclosure dengan stack trace internal: sedang.
- Introspection terbuka pada endpoint publik tanpa data sensitif: rendah atau informatif.

## Stop Conditions

- Respons menunjukkan data lintas akun yang tak seharusnya → berhenti, redact, laporkan (ROADMAP §10).
- Latensi naik signifikan atau repeated 5xx setelah query depth uji → berhenti (ROADMAP §10).
- Budget habis atau approval dicabut → berhenti.

## Output Format

- Peta schema yang teramati (bila tersedia) beserta field sensitif yang diidentifikasi.
- Hasil uji per area: introspection, otorisasi resolver, kontrol resource, error disclosure — tiap baris observation dengan bukti.
- Daftar rute lanjutan per temuan.

## Related Skills

- `rest-api-testing` — sisi REST dari API yang sama.
- `idor-and-bola` — rute temuan akses lintas akun pada resolver.
- `api-security-methodology` — konteks prioritas permukaan API.
- `http-proxy-traffic-analysis` — sumber baseline query dari history.
- `vulnerability-validation`, `false-positive-analysis` — kontrak validasi dan triase.
