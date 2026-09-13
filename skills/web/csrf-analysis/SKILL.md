---
name: csrf-analysis
description: >
  Use when auditing state-changing requests for cross-site request forgery
  protection: inventory token handling and cookie attributes from recorded
  traffic, replay protected actions without or with a wrong token from a
  second account context, and judge protection from the acceptance or
  rejection differential.
version: 0.1.0
risk: medium
requires_credentials: true
---

# CSRF Analysis

## Purpose

- Menganalisis proteksi anti-CSRF pada request state-changing: keberadaan dan validasi token anti-CSRF, atribut SameSite cookie, dan validasi Origin/Referer.
- Menilai proteksi dari differential: replay aksi yang sama TANPA token, dengan token salah, atau dari konteks akun berbeda — lalu bandingkan diterima atau ditolak.
- Mencakup login CSRF dan boundary antar user pada aksi yang bisa dipicu lintas sesi.

## When To Use

- Endpoint state-changing (POST/PUT/PATCH/DELETE) perlu dinilai ketahanannya terhadap pemanggilan lintas situs.
- Form atau API memakai token anti-CSRF dan perlu dipastikan apakah token benar-benar divalidasi server, per-request atau per-session.
- Dua akun uji tersedia sebagai credential reference (konteks victim dan attacker).

## When Not To Use

- Hanya satu akun tersedia — differential antar konteks tidak bisa dibangun.
- Request yang dianalisis read-only (GET tanpa efek samping) — bukan permukaan CSRF.
- Authorization `pending` atau approval HIGH untuk replay stateful belum ada (ROADMAP §8).
- Program terms melarang replay aksi stateful dengan akun uji.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; replay stateful berstatus HIGH → approval eksplisit per endpoint dengan budget minimal (ROADMAP §8, §9).
- Aksi uji dipilih yang benign dan reversible pada akun uji sendiri (mis. pengubahan preferensi tampilan); aksi irreversible (perubahan email, password, pembayaran, hapus data) tidak dipakai sebagai target iterasi.
- Dua account reference sah (victim, attacker); nilai kredensial tidak pernah masuk konteks (ROADMAP §23).
- Semua replay menargetkan akun uji; tidak pernah menyentuh user nyata.

## Required Context

- Inventaris request state-changing dari history: method, path, parameter, dan keberadaan field token anti-CSRF.
- Atribut cookie sesi dari request terekam: SameSite, Secure, domain — untuk menilai lapisan proteksi browser.
- Baseline request sukses (dengan token valid) dari konteks victim.
- Pemahaman fungsi endpoint: sensitif atau trivial, reversible atau tidak.
- Pola validasi yang tampak: pesan penolakan, perbedaan respons saat token tidak ada.

## Required Capabilities

- `list_history` — menginventarisasi request state-changing beserta token dan cookie yang menyertainya.
- `inspect_request` — memeriksa header Cookie, field token, dan header Origin/Referer pada request terekam.
- `request_replay` — menjalankan ulang aksi state-changing dengan satu variasi per iterasi: tanpa token, token salah, konteks akun berbeda.
- `response_comparison` — membandingkan hasil antar variasi untuk menilai validasi server.
- Skill tidak menentukan provider; replay stateful hanya berjalan di provider proxy dengan approval HIGH aktif (ROADMAP §4.1, §5.2, §8).

## Required Credentials

- Pengujian menuntut dua konteks akun: victim (pemilik aksi baseline) dan attacker (konteks pembanding) — frontmatter menyatakan `requires_credentials: true`.
- Akun disebut sebagai reference (`account-a`, `account-b`); nilai kredensial di-inject control plane saat eksekusi dan tidak pernah masuk konteks (ROADMAP §23).
- Jangan minta user menempelkan nilai kredensial; jangan menyalinnya ke evidence.
- Evidence dari request authenticated wajib tersanitasi sebelum dipersist (ROADMAP §23, §25).

## Core Concepts

- **Differential sebagai diskriminan**: server yang memvalidasi token akan menolak variasi tanpa token atau dengan token salah; perbedaan hasil itulah temuan, bukan teks pesan.
- **Token anti-CSRF**: presence (ada atau tidaknya field), validation (diperiksa server atau diabaikan), scope (per-request vs per-session), dan binding (terikat sesi atau bisa dipakai lintas akun).
- **SameSite cookie**: Lax memblokir cookie pada cross-site POST dari browser; None mengirim selalu; atribut ini dinilai dari cookie terekam, bukan dari replay.
- **Origin/Referer validation**: lapisan server-side lain — dinilai dengan replay yang mengubah Origin/Referer, satu variasi per iterasi.
- **Login CSRF**: fungsi login tanpa proteksi memungkinkan sesi korban terikat akun penyerang — dinilai dari keberadaan proteksi pada request login, bukan dari serangan nyata.
- **Boundary antar user**: token milik akun A yang diterima pada konteks akun B menunjukkan token tidak terikat sesi — dinilai dari differential, bukan dari penyerangan user lain.

## Reasoning Workflow

1. Inventarisasi endpoint state-changing dari history; klasifikasikan berdasar sensitivitas dan reversibility.
2. Untuk tiap kandidat, catat keberadaan field token, atribut cookie sesi, dan header Origin/Referer yang terkirim.
3. Pilih satu endpoint uji yang benign dan reversible; rekam baseline sukses dari konteks victim.
4. Ajukan approval HIGH scoped; jalankan replay dari konteks attacker TANPA token — satu variasi.
5. Lanjutkan variasi berikutnya satu per satu: token salah atau statik, token milik akun lain, Origin/Referer tidak valid.
6. Bandingkan hasil tiap variasi dengan baseline: diterima (proteksi lemah) atau ditolak dengan pola tertentu (proteksi bekerja — catat lapisannya).
7. Jalankan FP check; susun narasi dampak lintas situs bila proteksi lemah; perbarui lifecycle (ROADMAP §26).

## Allowed Operations

- Replay aksi state-changing pada akun uji sendiri dengan satu variasi token atau Origin per iterasi, dalam budget approval HIGH.
- Pemilihan endpoint uji yang benign dan reversible; pemulihan efek bila fitur menyediakannya.
- Analisis cookie, token, dan header dari data terekam tanpa eksekusi.

## Approval Requirements

- Semua replay stateful berstatus HIGH: approval eksplisit per endpoint, method, path, account reference, budget kecil, dan expiry (ROADMAP §8, §9).
- Endpoint stateful baru berarti approval baru; jangan memperluas iterasi di luar endpoint yang disetujui.
- Approval dicabut atau kadaluarsa → berhenti; renewal sebagai approval baru (ROADMAP §9, §10).

## Forbidden Operations

- Replay aksi irreversible atau bernilai tinggi (perubahan email/password, transaksi, hapus data) sebagai target iterasi.
- Menyentuh akun atau data user nyata; semua iterasi terbatas pada akun uji.
- Membangun halaman atau proof-of-concept yang benar-benar dipicu dari browser korban nyata.
- Menggabungkan beberapa variasi dalam satu request.
- Melanjutkan eksekusi setelah side effect tidak terduga (ROADMAP §10).

## Evidence Requirements

- Minimum set ROADMAP §25: baseline evidence, reproduction steps, expected behavior, actual behavior, impact, false-positive analysis, scope reference, confidence, sanitized artifact.
- Matriks variasi per endpoint: baseline (token valid), tanpa token, token salah, token lintas akun, Origin/Referer bervariasi — dengan hasil (diterima atau ditolak) dan account reference tiap baris.
- Atribut cookie dan keberadaan token dicatat dari request terekam, bukan dari asumsi.
- Narasi dampak lintas situs: skenario penyerang, yang bisa dilakukan, dan lapisan proteksi yang tersisa (SameSite, Origin check).

## False Positive Checks

- Server memang memvalidasi: variasi ditolak dengan pola konsisten — proteksi bekerja; bedakan penolakan auth umum dari penolakan token.
- SameSite=Lax pada cookie sesi memblokir cross-site POST dari browser meski server tidak memvalidasi token — risiko tersisa biasanya terbatas pada cross-site GET top-level.
- Request read-only atau idempotent tanpa efek state — bukan permukaan CSRF.
- Respons tetap 200 tetapi berisi pesan penolakan — periksa isi respons, bukan hanya status.
- Origin tester ditolak padahal token juga lemah — periksa apakah penolakan datang dari validasi Origin/Referer, bukan dari token.

## Severity Guidance

- Aksi sensitif (perubahan kredensial, transfer, perubahan role) tanpa validasi token dan tanpa SameSite → tinggi.
- Login CSRF → sedang hingga tinggi, tergantung dampak sesi terikat akun penyerang.
- Token per-session yang tetap divalidasi → umumnya risiko rendah; catat sebagai saran pengkuatan, bukan temuan tinggi.
- Endpoint dengan lapisan ganda (token + SameSite + Origin check) → kemungkinan bukan temuan; catat arsitektur proteksinya.
- Differential yang berasal dari fungsi trivial (preferensi tampilan) → rendah; severity mengikuti dampak aksi yang dipengaruhi.

## Stop Conditions

- Side effect tidak terduga pada akun uji (data berubah di luar ekspektasi) → stop, catat, pulihkan bila memungkinkan (ROADMAP §10).
- Akun uji terkunci atau diskors → hentikan alur berbasis akun itu.
- Respons memuat data sensitif lintas akun → stop, redact, laporkan (ROADMAP §10).
- Budget habis, approval dicabut, atau authorization expired → stop (ROADMAP §10).

## Output Format

- Profil proteksi per endpoint: token (ada, divalidasi, scope), SameSite, Origin/Referer, hasil matriks variasi.
- Kesimpulan per endpoint: terlindungi (lapisan mana), lemah (differential mana), atau tidak conclusif.
- Referensi evidence (hash + path) untuk baseline dan tiap variasi.

## Related Skills

- `web-authorization` — pembeda: authorization menjawab "boleh akun ini", CSRF menjawab "apakah ini kemauan user".
- `idor-and-bola` — differential antar akun dengan pola serupa pada object authorization.
- `web-authentication` — konteks sesi dan login CSRF.
- `http-proxy-request-replay`, `http-proxy-response-comparison` — operasi inti yang dipakai.
- `false-positive-analysis` — triase sebelum status naik.
- `vulnerability-validation` — kerangka lifecycle finding (ROADMAP §26).
