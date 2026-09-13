---
name: web-authentication
description: >
  Use when analyzing how a web application authenticates users — session
  cookies, bearer-style tokens, or SSO redirects — including logout
  invalidation and session fixation, with test accounts referenced by name
  only and every active step behind an approved scoped replay.
version: 0.1.0
risk: medium
requires_credentials: true
---

# Web Authentication

## Purpose

- Menganalisis mekanisme authentication aplikasi web — session cookie, token bearer-style, atau alur SSO — beserta kualitas lifecycle sesinya.
- Menguji perilaku kritis sesi dengan replay terkontrol ber-approval: logout invalidation, session fixation, dan penanganan sesi kedaluwarsa.
- Menjaga batas kredensial: akun uji hanya dirujuk sebagai reference; skill ini bukan jalur credential attack.

## When To Use

- Surface mapping menemukan alur login/logout/refresh dan hypothesis dibentuk atas mekanismenya.
- Engagement punya test account yang sah dan credential reference sudah tersedia (ROADMAP §23).
- Program terms mengizinkan pengujian session lifecycle dengan akun uji.

## When Not To Use

- Tidak ada test account atau credential reference tidak tersedia — jangan menguji dengan akun milik user sungguhan.
- Authorization `pending` — analisis pasif dari history boleh berjalan, seluruh replay ditunda.
- Yang dicari adalah kelemahan menebak kredensial atau stuffing — kategoris dilarang di seluruh project (ROADMAP §2, §22).
- Target mekanisme auth adalah IdP pihak ketiga yang out-of-scope.

## Authorization Preconditions

- Status authorization `granted` atau `offline-lab`, dengan scope entry eksplisit untuk host yang diuji.
- Setiap replay authenticated butuh approval scoped yang mencantumkan account reference (ROADMAP §9).
- Test account hanya lewat credential reference yang dikelola credential provider; nilainya tidak pernah masuk konteks (ROADMAP §23).
- Penggunaan lebih dari satu akun untuk perbandingan disepakati program terms.

## Required Context

- Alur login/logout/refresh yang terekam di history, dari web-surface-mapping atau http-proxy-traffic-analysis.
- Credential reference yang sah, mis. `account-a`, `account-b`.
- Indikasi mekanisme sesi dari history: nama cookie sesi (tanpa nilainya), header otorisasi bertipe bearer, redirect IdP.
- Batasan program: kebijakan lockout, batas pengujian akun, larangan khusus.

## Required Capabilities

- `list_history` — menarik alur authentication yang sudah terekam sebagai baseline.
- `inspect_request` — membedah request authenticated: struktur sesi, header, dan cookie fungsional tanpa nilainya.
- `request_replay` — menjalankan pengujian lifecycle (mis. replay request setelah logout) di dalam approval aktif.
- `response_comparison` — membandingkan respons sebelum dan sesudah peristiwa sesi (logout, refresh, rotasi).

Skill tidak menentukan provider; capability berjaringan hanya dijalankan provider proxy (ROADMAP §4.1, §5.2).

## Required Credentials

- Skill ini bekerja pada alur authenticated, sehingga frontmatter menyatakan `requires_credentials: true`.
- Hermes hanya melihat reference seperti `account-a` atau `account-b`; nilai kredensial disimpan di credential store terpisah dan di-inject control plane saat eksekusi (ROADMAP §23).
- Jangan pernah meminta user menempelkan nilai kredensial ke percakapan, evidence, atau report.
- Setiap evidence dari request authenticated wajib melewati sanitasi otomatis sebelum dipersist (ROADMAP §23, §25).
- Authorization yang kadaluarsa membuat credential reference terkait tidak lagi bisa dipakai.

## Core Concepts

- **Session lifecycle**: diterbitkan (login), diperbarui (refresh), dicabut (logout/expiry) — tiap fase adalah titik uji.
- **Logout invalidation**: sesi yang di-logout harus benar-benar mati di server, bukan hanya hilang dari browser.
- **Session fixation**: sesi yang diketahui sebelum login tidak boleh tetap valid setelah login.
- **Credential reference**: akun uji disebut namanya, tidak pernah nilainya (ROADMAP §23).
- **Observation, bukan bypass**: respons yang berubah setelah mutasi sesi adalah observation; status vulnerability ditetapkan lewat alur validasi (ROADMAP §17, §22).

## Reasoning Workflow

1. Petakan alur authentication dari history: endpoint login, logout, refresh, dan mekanisme sesinya.
2. Kumpulkan baseline request authenticated per akun lewat `inspect_request`, tanpa menyalin nilai kredensial ke konteks.
3. Rumuskan hypothesis yang falsifiable, mis. "sesi masih valid setelah logout".
4. Ajukan approval scoped untuk replay yang akan diuji, termasuk account reference dan budget kecil (satu digit request per iterasi).
5. Jalankan uji lifecycle satu per satu — logout lalu replay request lama, atau uji fixation bila alur login mengizinkan — dengan satu variabel per iterasi.
6. Bandingkan respons antar fase sesi dengan `response_comparison`; catat pola status, body, dan header.
7. Jalankan false-positive check sebelum menaikkan status hypothesis, lalu simpan evidence lewat evidence-handling.

## Allowed Operations

- Replay request authenticated ber-method aman (GET) di dalam budget approval, dengan jeda antar request sesuai rate limit yang disetujui.
- Pengujian logout invalidation: satu request sesudah logout per iterasi, cukup untuk membuktikan hidup/mati sesi.
- Pengujian session fixation bila alur login terekam memungkinkannya, dengan approval eksplisit.
- Perbandingan dan analisis respons antar sesi.

## Approval Requirements

- Semua replay authenticated butuh approval scoped: capability, host, method, path, account reference, budget, dan expiry (ROADMAP §9).
- Method stateful pada alur auth (POST login/logout) tergolong risk HIGH → approval eksplisit sebelum eksekusi (ROADMAP §8).
- Approval yang kadaluarsa wajib dibuat ulang; pencabutan berarti berhenti total (ROADMAP §9).
- Percobaan login berulang atau menebak kredensial bukan hal yang bisa di-approve — kategoris terlarang (ROADMAP §2, §22).

## Forbidden Operations

- Credential stuffing, menebak kredensial, atau pengujian policy kata sandi dengan kombinasi kandidat.
- Menyimpan atau menyalin nilai kredensial ke konteks, evidence, log, atau report.
- Menguji IdP pihak ketiga atau domain out-of-scope yang muncul di alur SSO.
- Memakai akun user sungguhan (bukan akun uji) sebagai subjek pengujian.
- Melanjutkan eksekusi setelah lockout terpicu atau stop condition lain (ROADMAP §10).

## Evidence Requirements

- Baseline request/response per fase sesi: login, authenticated, logout, dan pasca-logout.
- Setiap replay mencantumkan account reference, waktu, dan posisinya dalam urutan uji — bukan nilai kredensial.
- Timeline sesi yang menghubungkan peristiwa (logout → replay) dengan hasil responsnya.
- Artifact tersanitasi dan ter-hash sesuai kontrak evidence-handling (ROADMAP §25).

## False Positive Checks

- Respons 401 pasca-logout bisa berasal dari expiry natural, bukan invalidation — bandingkan timing.
- Cache bisa menyajikan respons authenticated ke sesi berbeda — verifikasi lewat header cache dan replay ulang.
- Perbedaan environment (lab vs produksi) dan clock skew bisa membuat sesi tampak mati atau hidup secara keliru.
- Redirect ke halaman login belum tentu berarti sesi mati — cek apakah request langsung menghasilkan data.

## Severity Guidance

- Sesi yang tetap valid pasca-logout dengan akses penuh: tinggi, karena pencabutan sesi gagal.
- Session fixation yang bisa dieksploitasi lintas browser: tinggi, tergantung dampak akun.
- Kelemahan kosmetik (cookie tanpa flag tertentu tanpa dampak nyata): rendah hingga informasional.
- Severity mengikuti dampak nyata terhadap akun, bukan kelangkaan tekniknya.

## Stop Conditions

- Lockout akun uji terpicu atau indikasi pembatasan aktif → berhenti; akun uji yang terkunci menghentikan seluruh alur uji berbasis akun itu (ROADMAP §10).
- Respons memuat data akun lain yang tidak diberi otorisasi → berhenti, redact, laporkan (ROADMAP §10).
- Stop condition umum §10 terpicu (authorization expired, budget habis, approval dicabut, dsb.) → status hypothesis berubah menjadi `inconclusive`.

## Output Format

- Authentication record: mekanisme sesi, alur yang dipetakan, uji yang dijalankan, hasil per uji, dan status hypothesis.
- Ringkasan kelemahan lifecycle (bila ada) dengan referensi evidence per klaim.
- Daftar akun uji yang dipakai (reference) dan kondisi akhirnya (sehat atau terkunci).

## Related Skills

- `web-authorization` — lanjutan alami: setelah mekanisme sesi dipahami, uji kontrol aksesnya.
- `idor-and-bola` — pengujian object-level dengan multi-akun.
- `jwt-and-token-analysis` — bila mekanisme sesinya berbasis token terstruktur.
- `http-proxy-request-replay`, `http-proxy-response-comparison` — operasi replay dan compare yang dipakai skill ini.
- `vulnerability-validation` — kontrak umum validasi hypothesis.
