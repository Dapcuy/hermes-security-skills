---
name: http-proxy-auth-flow-analysis
description: >
  Use when reconstructing authentication flows from proxy history: login
  endpoints and redirects, refresh flows, logout invalidation, session
  rotation, cookie attribute hygiene, and multi-step authentication —
  passive first, active confirmation only.
version: 0.1.0
risk: medium
requires_credentials: true
---

# HTTP Proxy Auth Flow Analysis

## Purpose

- Merekonstruksi alur autentikasi dari proxy history: endpoint, parameter, redirect, dan urutan step dari anonim menjadi terautentikasi.
- Mengevaluasi kualitas siklus sesi: rotasi identifier setelah login, invalidation saat logout, dan kebersihan atribut cookie (Secure, HttpOnly, SameSite).
- Menegaskan prinsip pasif dulu: analisis dibangun dari history; replay aktif hanya untuk menutup pertanyaan yang tidak bisa dijawab dari data terekam.

## When To Use

- History memuat alur login/refresh/logout dari akun uji dan perlu dipahami sebelum pengujian authorization.
- Dugaan session fixation (identifier sesi tidak berubah setelah login) terlihat dari history dan perlu dipastikan.
- Multi-step authentication (OTP/MFA) perlu dipetakan sebagai masukan skill lain.

## When Not To Use

- History tidak memuat alur autentikasi — minta capture baru dari akun uji, jangan menebak.
- Pengujian kekuatan kredensial atau credential attack — dilarang mutlak (ROADMAP §2, §22).
- Bedah klaim token mendalam → `jwt-and-token-analysis`; skill ini pada level alur dan sesi.

## Authorization Preconditions

- Membaca history tidak menuntut status khusus; konfirmasi aktif butuh `granted` atau `offline-lab` plus approval (ROADMAP §8, §9).
- Alur yang dianalisis dan diuji hanya milik akun uji sebagai credential reference (ROADMAP §23).
- Konfirmasi yang mengakhiri sesi (logout) dinyatakan eksplisit di approval karena memengaruhi state akun uji.

## Required Context

- History alur lengkap dari akun uji: anonim → login → sesi → refresh → logout, dengan waktu tiap request.
- Daftar cookie beserta atributnya dari pembacaan header per request.
- Program terms soal pengujian autentikasi (sebagian program melarang interaksi dengan endpoint login).
- Tujuan analisis: peta alur untuk skill lain, atau verifikasi hipotesis spesifik (fixation, invalidation).

## Required Capabilities

- `list_history` — menarik dan menyusun urutan request alur autentikasi.
- `inspect_request` — membedah header Set-Cookie, atribut cookie, redirect, dan parameter body tiap step.
- `request_replay` — konfirmasi aktif terbatas atas hipotesis tersisa, di dalam approval.
- `response_comparison` — membandingkan respons antar step dan antar kondisi sesi.

Analisis pasif (dua capability pertama) tidak mengirim traffic; replay hanya berjalan pada provider proxy dengan privilege egress (ROADMAP §4.1, §5.2, §11).

## Required Credentials

- Minimal satu akun uji sebagai credential reference untuk alur yang dianalisis; nilai tidak pernah masuk reasoning (ROADMAP §23).
- Jangan menganalisis atau menguji alur milik akun nyata lain yang tercampur di history — filter, dan laporkan bila tercampur.
- Konfirmasi logout/rotation hanya pada sesi milik akun uji.
- Evidence yang memuat identifier sesi wajib ter-redact sebelum persist (ROADMAP §25).

## Core Concepts

- **Alur sebagai rantai**: login, redirect, penerbitan sesi, refresh, dan logout dibaca sebagai urutan request — bukan endpoint tunggal.
- **Session rotation**: identifier sesi wajib berubah saat naik privilege (anonim → terautentikasi); yang tetap adalah dugaan fixation.
- **Logout = invalidation server-side**: logout yang hanya menghapus cookie di klien tanpa mencabut sesi di server menyisakan sesi hidup.
- **Atribut cookie**: Secure, HttpOnly, dan SameSite dibaca dari Set-Cookie di history; kekurangan atribut adalah observation berdampak kontekstual.
- **Refresh flow**: endpoint refresh, rotasi token, dan nasib token lama setelah diputar terbaca dari urutan history.
- **Pasif dulu, aktif sekunder**: replay hanya untuk menjawab pertanyaan spesifik yang tersisa — bukan untuk melengkapi pemetaan yang bisa dibaca dari data.

## Reasoning Workflow

1. Filter history ke alur akun uji; susun timeline: request, waktu, status, dan redirect per step.
2. Identifikasi endpoint autentikasi: login, callback, OTP, refresh, logout — beserta parameter yang dikirim.
3. Bedah cookie: identifier sesi sebelum versus sesudah login (rotation), atribut Set-Cookie, dan scope path/domain.
4. Telusuri refresh: kapan dipanggil, apakah token diputar, dan apakah token lama masih dipakai setelahnya.
5. Evaluasi logout dari history: cari indikasi pencabutan server-side; tandai pertanyaan yang tak terjawab.
6. Konfirmasi aktif terbatas lewat approval: replay kecil untuk hipotesis spesifik (mis. sesi pasca-logout masih diterima).
7. Bandingkan respons antar step lewat perbandingan respons; catat anomali sebagai observation dengan referensi request id.
8. Serahkan peta alur ke skill pengujian authorization dan token sebagai masukan.

## Allowed Operations

- Membaca dan memfilter history tanpa batas jumlah; membedah request/response individu.
- Konfirmasi replay kecil (satu digit request) hanya untuk hipotesis tersisa, di dalam approval.
- Pencatatan peta alur, tabel cookie, dan temuan di case memory.

## Approval Requirements

- Analisis pasif tanpa approval; konfirmasi aktif butuh approval scoped: host, path, akun reference, budget, expiry (ROADMAP §9).
- Konfirmasi yang mengakhiri sesi dinyatakan eksplisit di approval karena memengaruhi state akun uji.
- Tidak ada pengujian terhadap akun selain yang dirujuk di approval.

## Forbidden Operations

- Credential attack dalam bentuk apa pun: guessing, stuffing, atau wordlist terhadap endpoint login (ROADMAP §2, §22).
- Menguji logout atau rotasi pada sesi milik pihak lain.
- Menyimpan nilai cookie atau session identifier di evidence tanpa redaksi (ROADMAP §23, §25).
- Replay aktif untuk "melengkapi" pemetaan yang bisa dijawab dari history.

## Evidence Requirements

- Timeline alur dengan referensi request id per step.
- Tabel cookie: nama, atribut, titik penerbitan, dan perubahan antar step — nilai ter-redact.
- Bukti konfirmasi aktif (bila ada): pasangan baseline-versus-replay dengan referensi approval.
- Daftar pertanyaan yang tidak terjawab beserta alasannya (data tipis, butuh capture baru).

## False Positive Checks

- Cookie tanpa Secure bisa berasal dari endpoint non-TLS yang memang terpisah — cek konteks sebelum mengklaim.
- Sesi yang tampak hidup setelah logout bisa karena cache respons, bukan invalidation gagal.
- Redirect berganda pada login bisa berupa flow SSO yang sah, bukan kelemahan.
- Identifier yang tidak berubah setelah login bisa bukan kredensial (cookie preferensi) — pastikan fungsinya dulu.

## Severity Guidance

- Session fixation terkonfirmasi: tinggi.
- Sesi tetap hidup di server setelah logout: sedang hingga tinggi sesuai masa hidup dan data.
- Cookie sesi sensitif tanpa HttpOnly: sedang (butuh jalur XSS untuk dieksploitasi).
- Kekurangan atribut tanpa jalur eksploitasi nyata: rendah atau informatif.

## Stop Conditions

- Akun uji terkunci atau suspended saat konfirmasi → hentikan (ROADMAP §10).
- Konfirmasi mengungkap sesi atau data pihak lain → berhenti, redact, laporkan (ROADMAP §10).
- Stop condition umum §10: budget habis, authorization expired, approval dicabut.

## Output Format

- Peta alur: step → endpoint → parameter → hasil, dengan referensi bukti per step.
- Penilaian rotasi, invalidation, dan atribut cookie per sesi (observation berkaidah).
- Daftar hipotesis tersisa yang butuh konfirmasi lanjutan oleh skill lain.

## Related Skills

- `web-authentication` — metodologi autentikasi web yang lebih luas.
- `jwt-and-token-analysis` — bedah klaim token hasil alur.
- `web-authorization`, `idor-and-bola` — penerima peta sesi untuk pengujian akses.
- `http-proxy-traffic-analysis` — segmentasi history di hulu.
- `vulnerability-validation`, `false-positive-analysis` — kontrak validasi dan triase.
