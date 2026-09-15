---
name: jwt-and-token-analysis
description: >
  Use when analyzing bearer-style tokens: claim structure and validation,
  expiry and revocation behavior, audience and issuer mismatches, refresh
  rotation, and token leakage — crafted tokens are used only to prove
  rejection, never to gain access.
version: 0.1.0
risk: medium
requires_credentials: true
---

# JWT and Token Analysis

## Purpose

- Menganalisis struktur dan siklus hidup token: klaim, expiry, revocation, rotasi refresh, dan pemakaian lintas endpoint.
- Menguji penolakan (rejection) server terhadap token invalid, expired, atau mismatched — tujuan akhirnya memastikan kontrol bekerja, bukan membuktikan akses.
- Menegaskan aturan etis skill ini: token hasil craft hanya untuk verifikasi penolakan; forged token yang DITERIMA server adalah stop condition dan laporan segera (ROADMAP §10, §28).

## When To Use

- API memakai JWT atau token bearer-style dan alur autentikasi sudah terpetakan dari history.
- History menunjukkan token di URL, token tercampur antar endpoint, atau refresh flow yang tidak jelas rotasinya.
- Setelah `web-authentication` memahami mekanisme sesi dan credential reference tersedia.

## When Not To Use

- Token opaque (bukan JWT) — tidak ada klaim untuk dibedah; perilaku revocation tetap bisa dinilai secara perilaku tanpa analisis struktural.
- Tanpa test account — analisis statis dari history boleh, tetapi uji penolakan tidak boleh dijalankan.
- Tujuannya mem-fabricate akses atau menaikkan privilege di luar verifikasi penolakan — dilarang mutlak.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; approval replay aktif untuk tiap endpoint yang diuji (ROADMAP §8, §9).
- Credential hanya sebagai reference; nilai di-inject provider saat eksekusi dan tidak pernah masuk reasoning (ROADMAP §23).
- Variasi token dibangun dari token akun uji sendiri; klaim identitas tetap milik akun uji — hanya atribut validitas yang divariasikan.

## Required Context

- Sampel request bertoken milik akun uji dari history, dengan nilai token ter-redact di catatan.
- Peta endpoint siklus token: penerbitan (login), pemakaian, refresh, logout, dan introspection bila ada.
- Klaim yang teramati: alg, iss, aud, exp/nbf, sub, dan klaim kustom beserta jangkauan waktunya.
- Kebijakan program tentang pengujian autentikasi dan pembuatan token.

## Required Capabilities

- `request_replay` — menjalankan variasi token (invalid, expired, mismatched) di dalam approval scoped.
- `response_comparison` — membandingkan respons token valid versus variasi untuk membaca perilaku validasi server.


## Required Credentials

- Minimal satu akun uji sebagai credential reference; nilai dikelola credential provider dan di-inject saat eksekusi (ROADMAP §23).
- Token milik akun lain tidak pernah menjadi bahan uji — pengujian lintas akun rutenya `idor-and-bola`.
- Variasi token hanya dibuat dari token akun uji sendiri dan hanya untuk menguji penolakan.
- Seluruh evidence yang memuat nilai token wajib ter-redact sebelum persist (ROADMAP §25).

## Core Concepts

- **Klaim sebagai kontrak**: alg, iss, aud, exp, dan sub menentukan siapa dan untuk apa token berlaku; ketidakcocokan salah satunya adalah hypothesis mismatch.
- **Rejection testing**: variasi token sah untuk memastikan server MENOLAK token tidak valid; penolakan yang konsisten adalah bukti kontrol bekerja.
- **Key confusion (teori dulu)**: keluarga serangan `alg: none` dan kebingungan asimetris-versus-simetris (HS/RS) dianalisis secara teori dari klaim dan perilaku server; uji aktif hanya bila server menerima variasi pada klaim milik akun uji sendiri dan approval mengizinkan.
- **Expiry dan revocation**: token yang masih diterima setelah logout atau rotasi adalah celah siklus hidup, terpisah dari benar-salahnya klaim.
- **Refresh rotation**: refresh token yang masih dipakai ulang setelah diputar menandakan rotasi tidak di-enforcement.
- **Token leakage**: token di URL bocor lewat log, referer, dan history — lokasi penyimpanan dan pengiriman token bagian dari temuan.

## Reasoning Workflow

1. Petakan siklus token dari history: endpoint penerbitan, pemakaian, refresh, dan pencabutan, dengan waktu tiap step.
2. Bedah klaim secara lokal (decode, nol traffic): catat alg, iss, aud, exp, dan klaim kustom; tandai yang janggal.
3. Susun matriks variasi: expired, signature tidak valid, mismatch iss/aud, token dari endpoint lain (token confusion), dan token pasca-logout.
4. Ajukan approval ber-budget kecil; jalankan variasi satu per satu terhadap endpoint akun uji sendiri.
5. Bandingkan respons tiap variasi dengan token valid: penolakan konsisten = kontrol bekerja; perbedaan halus antar variasi = observation.
6. Bila server MENERIMA token yang seharusnya ditolak — berhenti total, simpan evidence minimum, laporkan segera; jangan gunakan token itu lebih lanjut (ROADMAP §10, §28).
7. Analisis teori key confusion dari temuan langkah 2-5; craft token hanya bila tujuannya membuktikan penolakan dan approval menyatakannya eksplisit.
8. Tutup dengan evaluasi siklus hidup: rotasi refresh, revocation pasca-logout, dan kebocoran lokasi penyimpanan token.

## Allowed Operations

- Decode dan analisis klaim secara lokal — nol traffic ke target.
- Replay variasi token terhadap endpoint akun uji sendiri, dalam budget satu digit request per variasi.
- Perbandingan respons antar variasi atas data hasil replay.

## Approval Requirements

- Approval scoped per endpoint dan per variasi: budget kecil, expiry pendek, akun reference tertulis (ROADMAP §9).
- Craft token (bila diperlukan) dinyatakan eksplisit di approval dengan tujuan verifikasi penolakan, bukan akses.
- Forgery yang berhasil di luar rencana approval adalah pelanggaran stop condition — dilaporkan, bukan dieksploitasi.

## Forbidden Operations

- Menggunakan forged token yang diterima untuk akses data atau aksi lanjutan — satu request pembuktian cukup, selebihnya stop.
- Membuat token dengan klaim identitas pengguna lain (naik akun) — pengujian lintas akun bukan wilayah skill ini.
- Menyimpan atau memindahkan nilai token ke evidence, report, atau knowledge tanpa redaksi (ROADMAP §23, §25).
- Mengirim token ke host lain untuk "menguji" — token hanya dikirim ke endpoint in-scope yang menerbitkannya.

## Evidence Requirements

- Matriks variasi × respons dengan referensi replay id dan klasifikasi penolakan/penerimaan.
- Analisis klaim dengan nilai ter-redact; nilai token penuh tidak pernah masuk evidence (ROADMAP §23, §25).
- Catatan siklus hidup: waktu logout versus penerimaan token terakhir, dan rotasi refresh yang teramati.
- Bila forged token diterima: evidence minimum (satu pasangan request-respons), laporan segera, tanpa iterasi lanjutan.

## False Positive Checks

- Clock skew antara penerbit dan verifikator membuat token tampak belum expired — toleransi detik hingga menit wajar.
- Endpoint introspection yang masih menerima token pasca-revoke bisa berarti cache introspection, bukan ketiadaan revocation.
- Token opaque bukan JWT — jangan paksa analisis struktural atas token tanpa klaim.
- Perbedaan respons antar endpoint bisa berupa desain (resource dan kebijakan berbeda), bukan token confusion.

## Severity Guidance

- Forged token diterima server, terutama pada variasi klaim identitas: kritikal — berhenti, lapor, jangan jelajahi.
- Token masih hidup setelah logout atau rotasi: sedang hingga tinggi, sesuai masa hidup dan sensitivitas data.
- Token dikirim via URL tanpa bukti akses tidak sah: sedang (kebocoran potensial lewat log/referer).
- Mismatch iss/aud yang DITOLAK dengan benar: bukan temuan — catat sebagai bukti kontrol bekerja.

## Stop Conditions

- Forged token DITERIMA server → hentikan semua pengujian, simpan evidence minimum, laporkan segera ke user (ROADMAP §10, §28).
- Respons memuat klaim atau token milik pihak lain → berhenti, redact, laporkan (ROADMAP §10).
- Akun uji terkunci akibat variasi pengujian → hentikan.
- Stop condition umum §10: budget habis, authorization expired, approval dicabut.

## Output Format

- Matriks variasi token × hasil penolakan/penerimaan dengan referensi bukti.
- Analisis klaim dan siklus hidup (expiry, revocation, rotasi) dengan nilai ter-redact.
- Status tiap hypothesis: kontrol bekerja, observation, atau stop-and-report.

## Related Skills

- `web-authentication` — pemahaman mekanisme sesi di hulu.
- `http-auth-flow-analysis` — pemetaan alur login/refresh/logout dari history.
- `idor-and-bola` — pengujian lintas akun (di luar wilayah skill ini).
- `api-rate-limit-analysis` — friksi percobaan pada endpoint refresh dan OTP.
- `vulnerability-validation`, `false-positive-analysis` — kontrak validasi dan triase.
