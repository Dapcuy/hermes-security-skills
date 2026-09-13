---
name: api-security-methodology
description: >
  Use when planning security testing for an API: classifying the API surface
  and mapping concern areas — authorization, input validation, rate limiting,
  mass assignment, documentation drift — to the specific skills that should
  run next.
version: 0.1.0
risk: medium
---

# API Security Methodology

## Purpose

- Menjadi peta metodologi pengujian keamanan API: mengklasifikasi permukaan API dan merutekan tiap area masalah ke skill spesifik.
- Menyeragamkan urutan: pemahaman auth scheme → authorization (object dan function level) → input validation → pembatasan laju → dokumentasi.
- Menegaskan bahwa skill ini merutekan, bukan mengeksekusi: tidak ada replay yang diminta dari sini.

## When To Use

- Target berbentuk API (REST, GraphQL, gRPC over HTTP) dan perencanaan pengujian dimulai.
- Permukaan API sudah terpetakan (web-surface-mapping atau openapi-analysis) dan perlu prioritas area.
- Hasil pengujian awal menunjukkan satu area masalah dan perlu dipastikan rutenya benar.

## When Not To Use

- Untuk mengeksekusi pengujian — skill ini tidak meminta capability aktif; eksekusi milik skill tujuan rute.
- Target bukan API (web halaman penuh) → mulai dari web-authorization dan skill web lain.
- Authorization dan scope belum terdokumentasi — engagement-scoping terlebih dulu.

## Authorization Preconditions

- Perencanaan boleh berjalan pada status authorization apa pun, tetapi tiap rute eksekusi hanya aktif pada `granted` atau `offline-lab`.
- Pengujian API yang menyentuh data lintas akun menuntut test account sebagai credential reference (ROADMAP §23).
- Rate limit yang berlaku di produksi adalah kontrol keamanan nyata: rencana menghormatinya, bukan mengujinya tanpa persetujuan eksplisit.

## Required Context

- Klasifikasi API: gaya (REST/GraphQL), auth scheme (session, bearer-style, key), dan versi.
- Inventaris endpoint dari openapi-analysis atau web-surface-mapping.
- Program terms: batasan pengujian, kebijakan rate limit, larangan khusus API.
- Test account yang tersedia (reference, ROADMAP §23).

## Required Capabilities

Skill ini tidak meminta capability aktif. Ia peta metodologi dan router: seluruh eksekusi berada di skill tujuan rute yang masing-masing meminta capability-nya sendiri, sesuai prinsip skill meminta capability bukan tool (ROADMAP §4.1). Pemetaan area ke skill ada di Core Concepts dan Related Skills.

## Core Concepts

- **Area masalah API**: authorization object-level, authorization function-level, input validation, mass assignment, rate limiting, dan documentation drift.
- **Mass assignment**: body yang menerima field lebih dari seharusnya (mis. field peran atau status) bisa mengubah state tanpa otorisasi khusus — diuji dengan menambah satu field per iterasi.
- **Rate limit adalah kontrol keamanan**: melewati batas dalam pengujian berarti mengganggu kontrol, bukan sekadar kesopanan.
- **Dokumentasi sebagai kontrak**: spesifikasi yang meleset dari realita adalah permukaan tersembunyi.

## Reasoning Workflow

1. Klasifikasikan permukaan API dan auth scheme-nya dari inventaris yang ada.
2. Urutkan area masalah berdasarkan dampak dan kesiapan data: authorization lebih dulu (dampak tertinggi, diskriminan jelas), lalu input, lalu pembatasan laju.
3. Rutekan tiap area: object-level → idor-and-bola; function-level → bfla; peran dan resource → web-authorization; input → payload-selection lalu injection-validation; drift spec → openapi-analysis.
4. Untuk mass assignment, susun rencana: satu field tambahan per iterasi, replay terkontrol, bandingkan respons — rutekan ke http-proxy-request-mutation.
5. Catat area yang tidak bisa diuji (tanpa akun, tanpa baseline) sebagai gap yang eksplisit.
6. Perbarui rute seiring hasil: temuan di satu area sering membuka area lain — mis. BOLA menandai endpoint yang juga layak dicek mass assignment.

## Allowed Operations

- Perencanaan, klasifikasi, dan penulisan rencana pengujian di case memory.
- Penetapan urutan prioritas area dan pemilihan skill tujuan.
- Mendokumentasikan gap dan prasyarat per area: akun, baseline, dan approval yang dibutuhkan.

## Approval Requirements

- Skill ini tidak mengeksekusi, jadi tidak mengurus approval — tiap skill tujuan mengurus approval-nya sendiri (ROADMAP §8, §9).
- Rencana yang dihasilkan wajib mencantumkan prasyarat approval per area agar eksekusi tidak menabrak policy.
- Pengujian rate limit produksi hanya direncanakan bila program terms mengizinkan dan rutenya menyatakan approval eksplisit.

## Forbidden Operations

- Menjalankan replay atau mutasi dari skill ini.
- Merutekan pengujian credential attack atau pemindaian massal — keduanya dilarang di seluruh project (ROADMAP §2, §22).
- Merencanakan pengujian di luar scope entry yang sah.

## Evidence Requirements

- Rencana pengujian: area, skill tujuan, prasyarat, urutan, dan alasannya.
- Catatan gap: area tanpa data, akun, atau baseline, beserta dampaknya pada cakupan.
- Keputusan routing yang berubah di tengah jalan dicatat beserta pemicunya.

## False Positive Checks

- API yang diklaim REST tetapi berperilaku RPC — klasifikasi yang salah membuat rute salah (mis. mass assignment tidak relevan untuk endpoint query-only).
- Endpoint yang tampak tanpa pembatasan laju karena history-nya tipis — keputusan butuh data yang cukup.
- Dokumentasi yang meleset bukan selalu temuan: spesifikasi internal yang memang tidak dipublikasikan perlu konteks.

## Severity Guidance

- Skill ini tidak menetapkan severity; severity lahir dari skill validasi di ujung rute.
- Urutan prioritas bukan proyeksi severity — area pertama diuji karena diskriminan jelas, bukan karena pasti berdampak besar.

## Stop Conditions

- Klasifikasi API tidak bisa dipastikan → berhenti dan minta konfirmasi user sebelum merutekan.
- Semua area kunci tidak punya prasyarat (tanpa akun, tanpa history) → laporkan ketidaklengkapan, jangan memaksakan rute.
- Program terms bertentangan dengan rencana → sesuaikan rencana, bukan terms.

## Output Format

- Peta rute: area masalah → skill tujuan → prasyarat → status (siap, diblokir, atau gap).
- Urutan eksekusi yang disarankan beserta alasannya.
- Daftar prasyarat yang harus dipenuhi user atau skill lain.

## Related Skills

- `idor-and-bola` — rute area object-level authorization.
- `bfla` — rute area function-level authorization.
- `web-authorization` — rute peran dan resource.
- `openapi-analysis` — rute documentation drift dan sumber inventaris.
- `payload-selection`, `injection-validation` — rute input validation.
- `http-proxy-request-mutation` — rute uji mass assignment.
- `api-rate-limit-analysis`, `graphql-security`, `rest-api-testing` — rute area lanjutan saat skill tersedia.
