---
name: web-authorization
description: >
  Use when mapping and testing role-based access control: building a role
  versus resource matrix from recorded traffic, then verifying suspect cells
  through scoped replays with test accounts referenced by name only.
version: 0.1.0
risk: medium
requires_credentials: true
---

# Web Authorization

## Purpose

- Membangun matrix access control: peran versus resource/action, berisi harapan akses (dari desain) dan akses terobservasi (dari replay terkontrol).
- Menguji authorization horizontal (antar pengguna setara) dan vertikal (lintas peran) melalui replay ber-approval.
- Menegaskan prinsip deny-by-default: sel matrix yang tidak bisa dibuktikan statusnya dianggap belum teruji, bukan otomatis aman.

## When To Use

- Aplikasi punya beberapa peran atau level akses dan test account per peran tersedia.
- Surface mapping menemukan resource yang tampaknya hanya untuk peran tertentu.
- Setelah web-authentication memahami mekanisme sesi, agar replay authorization sah secara sesi.

## When Not To Use

- Tidak ada test account per peran — matrix bisa disusun, tetapi sel tidak boleh dinyatakan teruji.
- Authorization `pending` atau approval replay belum ada.
- Targetnya object-level per pengguna → idor-and-bola; targetnya fungsi admin → bfla; skill ini kerangka matrix-nya.

## Authorization Preconditions

- Status `granted` atau `offline-lab`, scope eksplisit, dan approval replay aktif untuk sel yang diuji (ROADMAP §8, §9).
- Test account per peran hanya sebagai credential reference (ROADMAP §23).
- Dampak data akibat pengujian dipahami owner; sel dengan efek stateful butuh approval risk HIGH.

## Required Context

- Inventaris endpoint dan resource dari web-surface-mapping.
- Baseline request per peran dari traffic terekam.
- Daftar peran dan harapan akses, dari dokumen aplikasi atau pernyataan user.
- Credential references per peran, mis. `account-admin`, `account-user`.

## Required Capabilities

- `request_replay` — menjalankan request peran rendah terhadap resource peran tinggi di dalam approval aktif.
- `response_comparison` — membandingkan respons lintas peran untuk menilai apakah akses benar-benar berbeda.

Skill tidak menentukan provider; replay hanya dijalankan provider proxy yang punya privilege egress (ROADMAP §4.1, §5.2, §11). Baseline per peran berasal dari traffic terekam lewat skill analisis traffic — skill ini menguji sel matrix, bukan menangkap traffic baru.

## Required Credentials

- Pengujian menuntut minimal satu akun per peran yang diuji, sehingga frontmatter menyatakan `requires_credentials: true`.
- Akun hanya dirujuk namanya; nilai dikelola credential provider dan di-inject saat eksekusi (ROADMAP §23).
- Jangan memakai akun produksi milik user nyata sebagai subjek pengujian.
- Evidence dari request authenticated wajib tersanitasi sebelum dipersist (ROADMAP §23, §25).

## Core Concepts

- **Matrix peran-resource**: baris peran, kolom resource/action, isi sel = allowed, denied, atau belum-teruji.
- **Horizontal vs vertical**: horizontal menukar identitas setara; vertikal menaikkan peran — dua arah serangan berbeda dengan diskriminan berbeda.
- **Authorization server-side**: penyembunyian di UI bukan kontrol; hanya penolakan di server yang berarti.
- **Deny-by-default**: kegagalan membuktikan akses bukan bukti keamanan — sel tanpa bukti tetap "belum teruji".
- **Satu sel per iterasi**: pengujian yang mengubah beberapa variabel sekaligus tidak bisa diatribusikan.

## Reasoning Workflow

1. Susun daftar resource/action dari inventaris dan peran yang tersedia.
2. Kumpulkan baseline request per peran dari history; tandai resource yang hanya muncul di peran tertentu.
3. Tulis matrix harapan: sel allowed/denied berdasar desain yang diklaim aplikasi.
4. Pilih sel suspect — denied menurut desain tetapi request-nya sederhana dan GET — dan ajukan approval scoped untuk masing-masing.
5. Uji satu sel per iterasi: replay request peran rendah ke resource peran tinggi, satu request per sel.
6. Bandingkan respons baseline peran tinggi versus hasil replay peran rendah; klasifikasikan denied (403/redirect), allowed (data setara), atau ambigu.
7. Isi matrix terobservasi, jalankan false-positive check untuk sel "allowed", lalu simpan evidence.

## Allowed Operations

- Replay GET untuk sel matrix dalam budget kecil per sel (satu digit request) dan rate limit yang disetujui.
- Perbandingan respons antar peran atas data hasil replay.
- Iterasi lanjutan atas sel yang masih ambigu, dengan approval baru bila budget sebelumnya habis.

## Approval Requirements

- Setiap sel yang diuji butuh approval scoped: host, path, method, account reference, budget, dan expiry (ROADMAP §9).
- Sel dengan method stateful (POST/PUT/PATCH/DELETE) berstatus risk HIGH → approval eksplisit dan pertimbangan dampak data (ROADMAP §8).
- Tidak ada perpanjangan diam-diam budget; pengujian baru memakai approval baru (ROADMAP §9).

## Forbidden Operations

- Menguji sel di luar matrix yang disepakati atau path out-of-scope.
- Mengubah data target secara permanen demi membuktikan akses (mis. menghapus resource milik peran lain).
- Menyimpulkan "allowed" dari respons sukses yang tidak berisi data peran lain.
- Menyimpan nilai kredensial di matrix, evidence, atau report.

## Evidence Requirements

- Matrix harapan dan matrix terobservasi, dengan sumber tiap sel (request id atau replay id).
- Pasangan baseline-versus-replay untuk setiap sel "allowed" yang diklaim.
- Catatan account reference per baris matrix.
- Artifact tersanitasi dan ter-hash (ROADMAP §25).

## False Positive Checks

- Respons 200 kosong atau berupa template halaman bukan bukti akses data — pastikan body memuat milik peran lain.
- Cache lintas sesi bisa mencemari perbandingan antar peran.
- Resource public (landing, aset statis) memang boleh diakses semua peran — bukan temuan.
- Error 500 pada replay bisa berarti kontrol gagal terbuka, bukan akses yang diberikan.

## Severity Guidance

- Vertical bypass ke fungsi atau data administratif: tinggi.
- Horizontal akses antar pengguna setara: tinggi bila data sensitif, sedang bila metadata terbatas.
- Inkonsistensi kecil tanpa dampak data: rendah.
- Severity mengikuti data yang terpapar, bukan jumlah sel yang lolos.

## Stop Conditions

- Akun uji berubah perilaku (lockout, suspended) → hentikan pengujian peran itu (ROADMAP §10).
- Respons memuat data sensitif tak terduga → berhenti, redact, laporkan (ROADMAP §10).
- Stop condition umum §10: authorization expired, budget habis, approval dicabut, repeated 5xx.

## Output Format

- Matrix peran-resource dengan status per sel: denied, allowed (dengan evidence), atau belum-teruji.
- Daftar temuan kandidat dengan pasangan baseline-versus-replay.
- Daftar sel yang tidak bisa diuji beserta alasannya (budget, akun tidak tersedia).

## Related Skills

- `idor-and-bola` — sisi horizontal yang objeknya spesifik per pengguna.
- `bfla` — sisi fungsi/aksi, bukan resource data.
- `web-authentication` — prasyarat pemahaman sesi.
- `multi-tenant-isolation` — varian batas tenant untuk arsitektur multi-tenant.
- `vulnerability-validation`, `false-positive-analysis` — kontrak validasi dan triase.
