---
name: rest-api-testing
description: >
  Use when executing hands-on REST API testing on top of a mapped surface:
  endpoint discovery from spec and history, HTTP method semantics, negative
  input testing, and verbose error handling — every anomaly recorded as an
  observation pending validation.
version: 0.1.0
risk: medium
---

# REST API Testing

## Purpose

- Menjadi lapisan eksekusi praktis di atas `api-security-methodology` (peta area) dan `openapi-analysis` (inventaris): membawa permukaan API yang sudah terpetakan menjadi pengujian terstruktur.
- Menguji semantik method HTTP (GET/POST/PUT/PATCH/DELETE) terhadap kontrak yang didokumentasikan, termasuk perilaku pada method yang tidak terdokumentasi.
- Menegaskan kontrak konsistensi respons: setiap anomali dicatat sebagai observation, bukan langsung finding — validasi dan severity ada di ujung pipeline (ROADMAP §26).

## When To Use

- Inventaris endpoint tersedia dari `openapi-analysis` atau history, dan authorization sudah `granted` atau `offline-lab`.
- Setelah `api-security-methodology` menetapkan urutan prioritas endpoint dan area.
- Endpoint undocumented-but-active ditemukan dan perlu dipahami perilaku dasarnya: status umum, struktur error, dan tipe data yang diterima.

## When Not To Use

- Target GraphQL → `graphql-security`; fokus pembatasan laju → `api-rate-limit-analysis`; bedah token → `jwt-and-token-analysis`.
- Belum ada baseline (spec maupun history) — pengujian tanpa pembanding hanya menghasilkan noise.
- Object-level authorization menjadi fokus utama → `idor-and-bola`; skill ini hanya menandai sinyalnya.

## Authorization Preconditions

- Status `granted` atau `offline-lab`, scope eksplisit per host/path, dan approval replay aktif untuk request yang dijalankan (ROADMAP §8, §9).
- Method stateful (POST/PUT/PATCH/DELETE) mengubah data: approval per endpoint wajib menyatakan dampaknya dengan risk HIGH.
- Test account bila dibutuhkan hanya sebagai credential reference (ROADMAP §23) — endpoint hasil discovery tetap wajib lolos scope validation.

## Required Context

- Inventaris endpoint gabungan: terdokumentasi (spec) dan terekam (history), beserta parameter dan schema body-nya.
- Baseline respons per endpoint: status umum, struktur body, header khas, dan ukuran tipikal.
- Program terms: endpoint yang dilarang disentuh stateful, kebijakan rate limit, dan larangan khusus program.
- Klasifikasi area dari `api-security-methodology` sebagai urutan pengujian.

## Required Capabilities

- `openapi_analysis` — mengekstrak path, method, parameter, dan schema dari spec sebagai rencana uji.

- `request_replay` — menjalankan request uji di dalam approval scoped.
- `response_comparison` — membandingkan respons baseline versus hasil variasi input.

Skill tidak menentukan provider; replay aktif hanya berjalan melalui provider proxy yang punya privilege egress (ROADMAP §4.1, §5.2, §11).

## Core Concepts

- **Method semantics**: GET hanya-baca, POST membuat, PUT mengganti utuh, PATCH mengubah sebagian, DELETE menghapus — server yang menerima mutasi lewat method yang salah adalah sinyal.
- **Discovery dua sumber**: spec mendokumentasikan niat, history menunjukkan realita; gabungan keduanya adalah daftar uji lengkap.
- **Negative testing**: input salah tipe, field wajib hilang, dan nilai batas menguji validasi server-side, bukan hanya jalur bahagia.
- **Error handling**: pesan error yang verbose (stack trace, versi framework, struktur query internal) adalah informasi bocor yang berdiri sendiri sebagai observation.
- **Anomali = observation**: respons yang menyimpang dari kontrak belum tentu vulnerability; ia hypothesis yang butuh validasi (ROADMAP §26).
- **Idempotency sadar data**: pengulangan PUT/DELETE yang aman secara spesifikasi bisa berbahaya secara data — pahami side effect sebelum mengulang.

## Reasoning Workflow

1. Gabungkan inventaris: endpoint dari spec (`openapi_analysis`) dan terekam (`list_history`); tandai undocumented-but-active.
2. Bangun baseline per endpoint: satu request normal per method terdokumentasi; catat status, struktur body, dan header.
3. Uji semantik method: method yang tidak terdokumentasi pada path yang sama, satu request per kombinasi, di dalam budget.
4. Jalankan negative testing terbatas: satu variasi per iterasi (salah tipe, field wajib hilang, nilai kosong), bandingkan dengan baseline.
5. Kumpulkan observasi error handling: status yang tidak sesuai kondisi, pesan yang membocorkan internal, dan inkonsistensi antar endpoint.
6. Rutekan sinyal lintas area: pola object-level → `idor-and-bola`; field berlebihan yang diterima → mass assignment via `http-request-mutation`.
7. Simpan matrix endpoint × uji × hasil sebagai evidence; tiap anomali berstatus observation dengan referensi request id.

## Allowed Operations

- Replay method terdokumentasi dan variasi method pada path yang sama, dalam budget satu digit request per kombinasi.
- Negative testing satu variasi per iterasi terhadap endpoint yang sudah punya baseline.
- Pencatatan, klasifikasi, dan routing anomali di case memory.

## Approval Requirements

- Approval scoped per endpoint: host, path, method, budget, dan expiry (ROADMAP §9).
- Method stateful butuh approval yang menyatakan dampak data dan berstatus risk HIGH (ROADMAP §8).
- Endpoint undocumented tetap wajib lolos scope validation sebelum diuji — keberadaan di history bukan izin.

## Forbidden Operations

- Fuzzing massal parameter atau path dari skill ini — content fuzzing milik skill khusus dengan wordlist dan budget tersendiri.
- Mengulang request stateful tanpa memahami side effect (penghapusan data, pengiriman notifikasi).
- Menyatakan anomali sebagai vulnerability tanpa validasi (ROADMAP §26).
- Mengirim payload destruktif atau eksfiltrasi (ROADMAP §22).

## Evidence Requirements

- Matrix endpoint × method × hasil dengan referensi request/replay id per sel.
- Pasangan baseline-versus-anomali untuk setiap observation yang diklaim.
- Daftar endpoint yang tidak diuji beserta alasannya (out-of-scope, tanpa approval, tanpa baseline).
- Artifact tersanitasi dan ter-hash (ROADMAP §25).

## False Positive Checks

- 405/406 pada method tak terdokumentasi bisa berarti routing framework, bukan kontrol yang disengaja.
- Verbose error di lingkungan staging/development bisa berupa konfigurasi lingkungan, bukan temuan produksi.
- Respons "berhasil" untuk input salah tipe bisa berarti coercion yang sah — cek apakah data benar-benar berubah.
- Perbedaan ukuran respons bisa berasal dari cache atau personalisasi, bukan bocoran data.

## Severity Guidance

- Anomali adalah observation; severity ditetapkan skill validasi setelah dampak terbukti (ROADMAP §26).
- Verbose error yang hanya membocorkan versi framework: rendah; yang membocorkan struktur internal atau query: sedang hingga tinggi sesuai data.
- Penyimpangan method semantics baru berdampak bila membuka akses atau mutasi tanpa otorisasi.

## Stop Conditions

- Repeated 5xx setelah variasi input → hentikan pengujian endpoint itu (ROADMAP §10).
- Respons memuat data sensitif tak terduga → berhenti, redact, laporkan (ROADMAP §10).
- Side effect tidak terduga dari method stateful (data berubah tanpa niat) → hentikan dan laporkan.
- Stop condition umum §10: budget habis, authorization expired, approval dicabut.

## Output Format

- Matrix pengujian endpoint × method × hasil (OK, anomali, tidak diuji) dengan referensi bukti.
- Daftar observation berkaidah: pasangan baseline-versus-anomali dan hipotesis penyebabnya.
- Daftar rute lanjutan: endpoint → skill validasi yang tepat.

## Related Skills

- `api-security-methodology` — peta area dan prioritas tempat skill ini bekerja.
- `openapi-analysis` — penyuplai inventaris spec dan deteksi drift.
- `idor-and-bola` — rute sinyal object-level authorization.
- `http-request-mutation` — rute uji mass assignment.
- `api-rate-limit-analysis`, `graphql-security`, `jwt-and-token-analysis` — rute abuse control dan token.
- `vulnerability-validation`, `false-positive-analysis` — kontrak validasi dan triase observation.
