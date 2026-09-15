---
name: oauth-security
description: >
  Use when analyzing OAuth 2.0 / OIDC flows of a target: authorization
  code flow (code interception, PKCE requirement), deprecated implicit
  flow, state and redirect_uri validation, token substitution, and scope
  escalation — passive flow mapping first, controlled replay to confirm.
version: 0.1.0
risk: medium
requires_credentials: true
---

# OAuth Security

## Purpose

- Menganalisis keamanan alur OAuth 2.0/OIDC pada target: endpoint authorization, callback, token exchange, dan parameter yang menentukan alurnya.
- Menilai proteksi authorization code flow: requirement PKCE, risiko code interception, dan kebersihan parameter alur.
- Mengidentifikasi pemakaian implicit flow yang deprecated beserta konsekuensi token yang terpapar di fragment URL.
- Menilai validasi state dan redirect_uri serta risiko token substitution dan scope escalation pada alur yang terekam.

## When To Use

- Target mengintegrasikan login OAuth/OIDC (sebagai client) dan history memuat alurnya.
- Dugaan state tidak divalidasi atau redirect_uri longgar terlihat dari parameter di history.
- Alur memakai response_type token/id_token (implicit) dan perlu dinilai risikonya.
- Dugaan scope escalation atau token substitution perlu dibuktikan dengan replay terkendali.

## When Not To Use

- Tidak ada alur OAuth/OIDC pada target — tidak ada permukaan yang dinilai.
- Bedah klaim token mendalam tanpa konteks alur — `jwt-and-token-analysis` lebih tepat.
- Credential attack terhadap authorization server atau endpoint token — dilarang mutlak (ROADMAP §2, §22).
- Menguji authorization server pihak ketiga di luar scope — hanya sisi client in-scope yang dinilai.

## Authorization Preconditions

- Membaca history alur tidak menuntut status khusus; replay konfirmasi butuh `granted`/`offline-lab` plus approval (ROADMAP §8, §9).
- Alur yang dianalisis dan diuji hanya milik akun uji sebagai credential reference (ROADMAP §23).
- Redirect terkait OAuth tunduk pada aturan no-follow dan re-validasi per hop (ROADMAP §29) — callback out-of-scope tidak pernah diikuti.
- Parameter OAuth (code, state, token) adalah data (ROADMAP §24); nilai token tidak pernah masuk reasoning atau evidence tanpa redaksi (ROADMAP §23).

## Required Context

- Peta endpoint OAuth dari history: authorization, callback/redirect_uri, token exchange (bila terlihat), dan refresh.
- Parameter alur per step: client_id, response_type, scope, state, redirect_uri, code_challenge/method, dan nonce.
- Program terms soal pengujian login/OAuth — sebagian program membatasi interaksi dengan authorization server.
- Account reference akun uji yang dipakai pada alur dan batas pemakaiannya (ROADMAP §23).

## Required Capabilities


- `request_replay` — konfirmasi terkendali: state dihapus/diubah, code direplay, tujuan callback divariasi, di dalam approval.
- `response_comparison` — membandingkan respons alur normal versus alur yang dimutasi.

Replay hanya berjalan pada provider proxy dengan egress dan approval scoped (ROADMAP §4.1, §5.2, §9).

## Required Credentials

- Minimal satu akun uji sebagai credential reference untuk alur yang dianalisis; nilai tidak pernah masuk reasoning (ROADMAP §23).
- Alur milik akun nyata lain yang tercampur di history tidak dianalisis dan dilaporkan ke user.
- Client secret aplikasi target bukan milik engagement dan tidak pernah diminta, disimpan, atau diuji.
- Evidence yang memuat code, state, atau token wajib ter-redact sebelum persist (ROADMAP §25).

## Core Concepts

- **Authorization code + PKCE**: risiko code interception dinilai dari kehadiran code_challenge/code_verifier; tanpa PKCE, code di callback URL rentan bocor lewat referrer, history browser, dan log.
- **Implicit deprecated**: response_type token/id_token menaruh token di fragment URL — skema ini tidak lagi direkomendasikan; keberadaannya adalah temuan konfigurasi.
- **State sebagai batas CSRF alur**: state yang tidak divalidasi membuka login CSRF dan penyambungan sesi pihak lain.
- **Redirect_uri exact-match**: validasi longgar (prefix, substring, path trailing) membuka kebocoran code/token ke endpoint pihak ketiga.
- **Token substitution**: token pihak lain yang diterima tanpa binding yang benar (audience/issuer) menunjukkan validasi yang lemah di sisi client.
- **Scope escalation**: scope yang bisa diperluas lewat parameter saat authorization ulang atau refresh menunjukkan otorisasi yang tidak di-pin di server.
- **Pasif dulu**: peta alur dibangun dari history; replay hanya untuk menutup pertanyaan spesifik yang tersisa.

## Reasoning Workflow

1. Susun timeline alur dari history: authorization request → consent (bila ada) → redirect/callback → token exchange → pemakaian token.
2. Katalogisasi parameter tiap step: response_type, scope, state, redirect_uri, PKCE challenge, dan nonce — catat dalam bentuk ter-redact.
3. Nilai proteksi code flow: PKCE ada/tidak, state ada/tidak, dan bentuk redirect_uri yang terdaftar.
4. Deteksi implicit flow dari response_type dan lokasi token (fragment URL pada callback).
5. Susun hypothesis berurutan risiko: state tidak divalidasi, redirect_uri longgar, code tanpa PKCE, scope escalation, token substitution.
6. Konfirmasi terkendali lewat replay: satu variabel per iterasi (mis. state dihilangkan), no-follow pada redirect keluar scope, dan perbandingan respons terhadap alur normal.
7. Klasifikasikan hasil sebagai observation berkaidah; rutekan temuan ke vulnerability-validation dengan dampak (account takeover, token leakage) sebagai hypothesis.

## Allowed Operations

- Membaca dan menyusun alur dari history tanpa batas jumlah entri, karena nol traffic.
- Replay konfirmasi satu variabel pada endpoint client in-scope, di dalam approval dan budget.
- Perbandingan respons antar kondisi alur (normal versus dimutasi) lewat capability comparison.
- Pencatatan peta alur, tabel parameter, dan temuan di case memory.

## Approval Requirements

- Analisis pasif tanpa approval; konfirmasi aktif butuh approval scoped: host, path, parameter yang dimutasi, akun reference, budget, dan expiry (ROADMAP §9).
- Mutasi state atau redirect_uri menyentuh endpoint login — nyatakan eksplisit di approval karena berdampak pada state akun uji.
- Konfirmasi yang memicu penerbitan token baru dibatasi jumlahnya dan dicatat; token hasil uji tidak dipakai melampaui kebutuhan bukti.
- Tidak ada pengujian terhadap akun selain yang dirujuk di approval.

## Forbidden Operations

- Credential attack dalam bentuk apa pun: menebak code/state secara brute-force atau wordlist terhadap endpoint authorization/token (ROADMAP §2, §22).
- Menguji alur milik akun atau sesi pihak lain yang tercampur di history.
- Mengikuti redirect callback ke domain out-of-scope (ROADMAP §29).
- Menyimpan code, state, token, atau client secret tanpa redaksi di evidence/report (ROADMAP §23, §25).
- Mengklaim account takeover dari substitusi token tanpa validasi penuh via kontrak vulnerability-validation (ROADMAP §26).

## Evidence Requirements

- Timeline alur dengan referensi request id per step dan parameter ter-redact.
- Tabel proteksi alur per client: PKCE, state, redirect_uri validation, dan response_type yang teramati.
- Bukti replay konfirmasi: request, respons, dan referensi approval per iterasi.
- Daftar pertanyaan tak terjawab (mis. validasi server-side yang tak terlihat dari klien) beserta alasannya.

## False Positive Checks

- PKCE bisa wajib di server walau tidak tampak di sampel history — jangan klaim "tanpa PKCE" dari satu alur yang tidak memuat code_challenge.
- State bisa divalidasi server-side walau nilainya tampak diabaikan — kegagalan validasi harus dibuktikan dengan replay yang tetap diterima.
- Redirect ke domain resmi provider OAuth yang sah bukan redirect_uri longgar.
- Sesi yang tampak hidup setelah logout bisa karena cache respons, bukan validasi yang gagal.
- Respons error generik pada replay bisa berarti validasi bekerja — baca body sebelum menyimpulkan.

## Severity Guidance

- Code/token interception terbukti (tanpa PKCE dikombinasikan dengan redirect_uri longgar): tinggi.
- Login CSRF via state yang tidak divalidasi: sedang; naik bila menyambung sesi pihak lain secara permanen.
- Implicit flow yang masih dipakai: sedang sebagai temuan konfigurasi deprekasi.
- Scope escalation terkonfirmasi: sedang hingga tinggi sesuai scope yang bisa dicapai.
- Severity final mengikuti kontrak vulnerability-validation; skill ini menetapkan status `suspected` dengan bukti alur.

## Stop Conditions

- Akun uji terkunci atau suspended saat konfirmasi → hentikan (ROADMAP §10).
- Konfirmasi mengungkap sesi atau data pihak lain → berhenti, redact, laporkan (ROADMAP §10).
- Authorization server menunjukkan pemblokiran atau rate limit → stop konfirmasi, cukupkan evidence pasif.
- Stop condition umum §10 terpicu: budget habis, approval dicabut, authorization expired.

## Output Format

- Peta alur OAuth per client: step, endpoint, parameter, dan proteksi yang teramati.
- Tabel temuan berkaidah: pola, bukti, status lifecycle, dan dampak yang diargumentasikan.
- Daftar hypothesis tersisa yang butuh konfirmasi lanjutan oleh skill validasi.

## Related Skills

- `http-auth-flow-analysis` — peta alur sesi/login umum yang menjadi dasar analisis OAuth.
- `jwt-and-token-analysis` — bedah klaim id_token/access token hasil alur.
- `redirect-analysis` — validasi redirect_uri dan rantai callback.
- `web-authentication` — konteks autentikasi web tempat OAuth terpasang.
- `vulnerability-validation` — kontrak validasi temuan alur.
- `false-positive-analysis` — triase sinyal alur yang ambigu.
