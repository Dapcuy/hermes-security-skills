---
name: cors-analysis
description: >
  Use when analyzing cross-origin resource sharing policy: inspect
  Access-Control-Allow-Origin and credentials headers from recorded
  traffic, replay read-only requests with different Origin values to test
  reflection and null-origin handling, and rate exposure by whether
  credentials and sensitive data are actually involved.
version: 0.1.0
risk: low
---

# CORS Analysis

## Purpose

- Menganalisis kebijakan CORS dari traffic terekam dan pengujian ringan: ACAO wildcard, reflect-origin, credentialed CORS (ACAO plus ACAC true), penanganan null origin, dan preflight.
- Menilai eksposur dari dua variabel utama: apakah origin penyerang diterima, dan apakah kredensial serta data sensitif benar-benar terlibat.
- Menjaga skill ini low-risk: replay read-only, tanpa mutasi state, tanpa enumerasi origin massal.

## When To Use

- Respons memuat header ACAO atau ACAC dan perlu dinilai apakah kebijakannya terlalu longgar.
- Endpoint mengembalikan data sensitif yang bisa terbaca lintas origin bila kebijakan salah.
- Sebelum menyusun temuan: wildcard, reflect-origin, dan kombinasi credentialed perlu didiskriminaskan.

## When Not To Use

- Endpoint tanpa header CORS dan tanpa kebutuhan lintas origin — tidak ada kebijakan untuk dinilai.
- Request yang butuh mutasi state — skill ini tidak menjalankannya.
- Authorization `pending`; replay ringan pun tetap butuh approval conditional (ROADMAP §8).
- Menguji browser, extension, atau aplikasi klien target — di luar jangkauan skill ini.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; approval conditional untuk replay dengan variasi Origin (ROADMAP §8, §9).
- Origin uji adalah domain milik tester yang menunjuk engagement (mis. domain canary) — bukan domain pihak ketiga.
- Semua replay read-only (GET/OPTIONS); tidak ada iterasi pada method stateful.
- Budget kecil: beberapa origin uji per endpoint, bukan enumerasi massal origin.

## Required Context

- Daftar endpoint ber-header CORS dari history: ACAO, ACAC, ACA-Methods, ACA-Headers, Vary.
- Skema autentikasi endpoint: cookie/session yang otomatis terkirim browser vs header token — menentukan dampak credentialed CORS.
- Sensitivitas data pada respons endpoint.
- Origin asal aplikasi (skema, host, port) sebagai referensi kebijakan yang dimaksud.

## Required Capabilities


- `inspect_request` — memeriksa header request (Origin, Referer, Cookie) dan header respons CORS pada traffic terekam.
- `request_replay` — mengulang request read-only dengan nilai Origin berbeda, satu variasi per iterasi.
- Skill tidak menentukan provider; replay hanya berjalan di provider proxy (ROADMAP §4.1, §5.2).
- Analisis preflight memakai replay method OPTIONS pada endpoint yang sama dalam approval yang berlaku.

## Core Concepts

- **Tiga bentuk kebijakan**: wildcard (`*`), reflect-origin (nilai Origin disalin ke ACAO), dan allowlist eksplisit — perilaku dan dampaknya berbeda.
- **Credentialed CORS**: ACAC true baru berbahaya bila cookie atau sesi otomatis terkirim; wildcard plus ACAC true tidak valid di browser, tetapi reflect-origin plus ACAC true adalah pola rawan.
- **Null origin**: Origin `null` (dari sandbox atau rantai redirect tertentu) yang diterima bersama ACAC true memperluas permukaan serangan.
- **Preflight**: OPTIONS dengan Access-Control-Request-Method dan Access-Control-Request-Headers memperlihatkan method serta header yang diizinkan lintas origin.
- **Pencocokan origin**: perbandingan harus lengkap (skema, host, port); kebijakan berbasis prefix atau substring adalah cacat yang dinilai dari variasi origin uji.
- **Vary: Origin**: respons yang di-cache tanpa Vary bisa menyajikan ACAO origin lain — kelas masalah tersendiri yang terlihat dari perilaku cache.

## Reasoning Workflow

1. Dari history, buat inventaris endpoint ber-header CORS beserta nilai ACAO/ACAC dan skema autentikasinya.
2. Klasifikasikan tiap endpoint: wildcard, reflect, atau allowlist; beri catatan kredensial dan sensitivitas data.
3. Rekam baseline request tanpa Origin; lalu replay dengan Origin canary milik tester dan bandingkan ACAO respons.
4. Variasi berikutnya satu per satu: Origin serupa-tapi-beda (menguji substring match), Origin null, dan origin subdomain bila relevan.
5. Untuk endpoint yang menarik, jalankan OPTIONS preflight dan catat method serta header yang diizinkan.
6. Nilai dampak: kombinasi (origin diterima) + (kredensial terkirim) + (data sensitif) menentukan severity; tanpa kredensial dampak jauh lebih rendah.
7. Jalankan FP check; perbarui lifecycle (ROADMAP §26).

## Allowed Operations

- Replay GET atau OPTIONS dengan variasi header Origin pada endpoint read-only, satu origin per iterasi, dalam budget approval.
- Jalankan OPTIONS preflight untuk membaca method dan header yang diizinkan lintas origin.
- Perbandingan header respons antar iterasi dan analisis statis traffic terekam.
- Dokumentasi matriks kebijakan per endpoint beserta referensi evidence.

## Approval Requirements

- Risk LOW dengan replay terbatas → approval conditional scoped per endpoint, dengan daftar origin uji dan budget kecil (ROADMAP §8, §9).
- Endpoint stateful atau replay non-read-only di luar scope skill ini — butuh skill dan approval lain.
- Approval kadaluarsa atau dicabut → berhenti (ROADMAP §9, §10).

## Forbidden Operations

- Enumerasi massal origin (wordlist origin panjang) — cukup beberapa origin uji yang bermakna.
- Replay method stateful atau request dengan efek samping.
- Menguji origin pihak ketiga yang tidak terkait engagement.
- Menyimpulkan dampak credentialed tanpa memeriksa skema autentikasi endpoint.
- Melanjutkan eksekusi setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Minimum set ROADMAP §25: baseline evidence, reproduction steps, expected behavior, actual behavior, impact, false-positive analysis, scope reference, confidence, sanitized artifact.
- Tabel per endpoint: nilai ACAO/ACAC baseline, respons per origin uji (reflected, null diterima), header Vary, skema auth, sensitivitas data.
- Kutipan header asli dari traffic terekam sebagai bukti utama; replay sebagai konfirmasi perilaku.
- Hash dan provenance tiap evidence (ROADMAP §25).

## False Positive Checks

- ACAO wildcard TANPA kredensial pada data publik → bukan temuan high; paling informasional.
- Reflect-origin pada endpoint yang datanya publik atau autentikasinya header-based (tidak otomatis terkirim browser) → dampak rendah.
- Origin internal yang "terreflect" ternyata echo header Host dari infrastruktur, bukan kebijakan CORS aplikasi.
- Respons cache lintas origin (tanpa Vary: Origin) bisa menampilkan ACAO milik origin lain — uji ulang tanpa cache sebelum menyimpulkan reflect.
- Preflight yang mengizinkan banyak header bukan berarti data sensitif terekspos — nilai bersama isi respons.

## Severity Guidance

- Reflect-origin plus ACAC true, cookie session, dan data sensitif → tinggi.
- Origin null diterima plus kredensial dan data sensitif → sedang hingga tinggi.
- Wildcard tanpa kredensial → rendah atau informasi; catat sebagai hygiene kecuali data sangat sensitif.
- Cacat pencocokan origin (substring atau prefix) dengan kredensial → sedang; naik bila origin yang lolos mudah diperoleh penyerang.

## Stop Conditions

- Respons replay memuat data sensitif yang tidak diperlukan → stop, redact, laporkan (ROADMAP §10).
- Rate limit terdeteksi atau repeated 5xx → stop (ROADMAP §10).
- Budget habis, approval dicabut, atau authorization expired → stop (ROADMAP §10).

## Output Format

- Matriks kebijakan CORS per endpoint: pola (wildcard, reflect, allowlist), ACAC, null origin, preflight, Vary, skema auth, sensitivitas.
- Kesimpulan dampak per endpoint beserta status lifecycle; endpoint tanpa isu dinyatakan bersih dengan bukti baseline.
- Referensi evidence (hash + path) untuk baseline dan tiap variasi origin.

## Related Skills

- `web-authorization` — CORS bukan otorisasi; kebijakan ini hanya membatasi pembacaan lintas origin oleh browser.
- `web-authentication` — skema cookie/session menentukan dampak credentialed CORS.
- `http-traffic-analysis`, `http-request-replay`, `http-response-comparison` — operasi inti yang dipakai.
- `false-positive-analysis` — triase sebelum status naik.
- `vulnerability-validation` — kerangka lifecycle finding (ROADMAP §26).
