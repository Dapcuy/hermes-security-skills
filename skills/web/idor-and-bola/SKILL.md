---
name: idor-and-bola
description: >
  Use when testing object-level authorization: taking a baseline request from
  account A, replaying the same object reference under account B, and judging
  access from the response difference, with false-positive checks for public
  resources and identifier encoding.
version: 0.1.0
risk: medium
requires_credentials: true
---

# IDOR and BOLA

## Purpose

- Metodologi pengujian object-level authorization (BOLA/IDOR): memastikan server memeriksa kepemilikan object, bukan hanya keabsahan sesi.
- Alur inti: baseline dengan akun A → replay object reference yang sama dengan identitas B → bandingkan respons.
- Menjaga pengujian tetap read-only-first dan di dalam approval, karena object yang diuji terikat pada akun lain.

## When To Use

- Endpoint mengembalikan atau mengubah resource yang terikat identifier milik pengguna: profil, order, dokumen.
- Dua test account tersedia sebagai credential reference (ROADMAP §23).
- Hypothesis sudah tercatat, mis. "akun B dapat membaca object akun A".

## When Not To Use

- Hanya satu akun tersedia — tanpa pembanding, hasil tidak bisa didiskriminkan.
- Yang diuji adalah fungsi atau aksi, bukan object data → bfla.
- Authorization `pending` atau approval replay belum ada.
- Program terms melarang penggunaan multi-akun.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; approval scoped per endpoint yang diuji, termasuk account reference kedua (ROADMAP §8, §9, §23).
- Object uji adalah data milik akun uji sendiri — jangan pernah memakai data user nyata sebagai target pengujian.
- Replay terhadap object di luar milik akun uji dilarang.

## Required Context

- Daftar endpoint dengan object reference dari web-surface-mapping, beserta tipe identifier-nya.
- Baseline request/response akun A dari history.
- Credential reference akun B.
- Pemahaman struktur identifier: numeric berurutan, UUID, hash, atau slug.

## Required Capabilities


- `request_replay` — menjalankan ulang request yang sama dengan identitas akun B melalui proxy.
- `response_comparison` — membandingkan respons akun A versus akun B untuk menilai akses object.

Skill tidak menentukan provider; replay hanya berjalan di provider proxy (ROADMAP §4.1, §5.2, §11). Injection kredensial dilakukan control plane saat eksekusi — skill hanya menyebut account reference.

## Required Credentials

- Pengujian menuntut minimal dua akun uji (A dan B), sehingga frontmatter menyatakan `requires_credentials: true`.
- Akun disebut sebagai reference (`account-a`, `account-b`); nilai kredensial tidak pernah masuk konteks dan di-inject saat eksekusi (ROADMAP §23).
- Jangan minta user menempelkan nilai kredensial; jangan menyalinnya ke evidence.
- Evidence dari request authenticated wajib tersanitasi sebelum dipersist (ROADMAP §23, §25).

## Core Concepts

- **Object reference**: identifier langsung (numeric id, UUID) maupun tak langsung (email, username, slug) — keduanya sama-sama harus diotorisasi.
- **Identifier acak bukan kontrol**: UUID yang sulit ditebak memperlambat enumerasi, tidak menggantikan otorisasi.
- **Baseline → swap → compare**: perbedaan respons antar identitas pada object yang sama adalah diskriminan utama.
- **Read-only-first**: mulai dari operasi baca; operasi tulis pada object milik akun lain berpotensi destruktif.

## Reasoning Workflow

1. Pilih endpoint dengan object reference yang jelas dari inventaris; catat tipe identifier dan letaknya (path, query, body).
2. Kumpulkan baseline akun A: request dan respons lengkap dari history.
3. Tulis hypothesis falsifiable: "akun B membaca object X milik akun A tanpa penolakan".
4. Ajukan approval scoped: endpoint, method, kedua account reference, budget kecil (satu replay per iterasi), dan expiry.
5. Jalankan replay dengan identitas akun B — injection kredensial oleh control plane — tanpa mengubah object reference.
6. Bandingkan respons: status, struktur body, dan keberadaan data akun A.
7. Jalankan false-positive check, lalu naikkan status hypothesis atau tutup sebagai inconclusive.

## Allowed Operations

- Replay baca (GET) object milik akun uji A dengan identitas akun uji B, satu request per iterasi, dalam budget approval.
- Variasi format identifier bila hypothesis mensyaratkan (mis. encoding berbeda dari object yang sama) — satu perubahan per iterasi.
- Perbandingan dan dokumentasi hasil.

## Approval Requirements

- Approval scoped per endpoint: capability, host, method, path, account reference B, budget, dan expiry (ROADMAP §9).
- Replay method stateful terhadap object milik akun lain berdampak data dan berstatus HIGH — butuh approval eksplisit, kesepakatan owner, dan umumnya ditahan di lab pada MVP (ROADMAP §8).
- Approval kadaluarsa berarti berhenti; renewal dibuat sebagai approval baru (ROADMAP §9).

## Forbidden Operations

- Mengiterasi identifier secara massal — pengujian ini satu object per iterasi, bukan pemindaian rentang id.
- Menyentuh object milik user nyata di luar akun uji.
- Operasi tulis/hapus pada object akun lain tanpa approval HIGH dan lingkungan lab.
- Menyimpan isi data akun (PII) mentah di evidence tanpa redaksi.

## Evidence Requirements

- Pasangan baseline (akun A) versus replay (akun B) pada object yang sama, dengan account reference, waktu, dan request id.
- Expected behavior (server menolak) versus actual behavior (server mengembalikan data) sesuai kontrak §25.
- Redaksi PII pada artifact; hash dan provenance tiap evidence (ROADMAP §25).
- Catatan tipe identifier dan lokasinya di request.

## False Positive Checks

- Resource ternyata public atau shared (mis. dokumen publik) — akses lintas akun memang disengaja.
- Encoding identifier berbeda makna: nilai terenkode atau ter-hash yang belum didekode bisa menunjuk object berbeda — pastikan kedua akun menunjuk object yang sama persis.
- Respons "sukses" tetapi isinya data akun B sendiri karena server menulis ulang object — bukan akses ke object A.
- Cache lintas sesi menyajikan respons akun A ke sesi B.
- Fitur kolaborasi (sharing, team workspace) yang memang mengizinkan akses antar akun.

## Severity Guidance

- Membaca data PII atau dokumen privat akun lain: tinggi.
- Membaca metadata minim tanpa konten sensitif: sedang.
- Menulis atau mengubah object akun lain tanpa otorisasi: tinggi hingga kritis, tergantung integritas data.
- Enumerability identifier saja, tanpa bukti akses lintas akun, bukan temuan BOLA.

## Stop Conditions

- Object uji tidak sengaja menunjuk data user nyata → berhenti memakai object itu dan laporkan.
- Akun uji terkunci → hentikan alur berbasis akun itu (ROADMAP §10).
- Respons memuat data sensitif tak terduga → redact dan laporkan (ROADMAP §10).
- Stop condition umum §10: budget habis, approval dicabut, authorization expired.

## Output Format

- Temuan kandidat per object: endpoint, identifier, pasangan baseline-versus-replay, kesimpulan akses, dan status lifecycle.
- Daftar endpoint yang diuji beserta hasilnya (menolak, bolong, atau tidak conclusif).
- Referensi evidence (hash + path) untuk tiap klaim.

## Related Skills

- `web-authorization` — kerangka matrix peran yang lebih luas.
- `bfla` — pengujian pada level fungsi, bukan object.
- `multi-tenant-isolation` — varian untuk batas tenant.
- `http-request-replay`, `http-response-comparison` — operasi inti yang dipakai.
- `false-positive-analysis` — triase sebelum status `reproduced`.
