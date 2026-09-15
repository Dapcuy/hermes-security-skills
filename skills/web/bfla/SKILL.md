---
name: bfla
description: >
  Use when testing function-level authorization: whether a low-privileged
  account can invoke administrative or sensitive functions, and how that
  differs from object-level (BOLA) testing in scope, evidence, and risk.
version: 0.1.0
risk: medium
requires_credentials: true
---

# BFLA

## Purpose

- Menguji function-level authorization (BFLA): apakah peran rendah bisa memanggil fungsi privileged — membuat pengguna, mengekspor data, atau aksi administratif lain.
- Memisahkan tegas temuan level fungsi dari object-level (BOLA): BFLA menyasar aksi/endpoint, bukan data milik pengguna lain.
- Menjaga dampak: fungsi yang diuji sering state-changing, sehingga pengujian dirancang untuk meminimalkan efek samping dan umumnya berjalan di lab.

## When To Use

- Inventaris menunjukkan endpoint fungsi administratif: management, export, user management.
- Test account peran rendah dan peran tinggi tersedia sebagai credential reference.
- Bisa diuji di offline-lab atau dengan data uji yang aman dan bisa di-roll-back oleh owner.

## When Not To Use

- Tidak ada akun peran rendah — tanpa itu tidak ada diskriminan.
- Fungsi mengubah atau menghapus data produksi nyata dan tidak bisa diamankan — jangan diuji langsung.
- Targetnya data object per pengguna → idor-and-bola.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; fungsi state-changing berstatus risk HIGH dan butuh approval eksplisit (ROADMAP §8).
- Approval scoped mencantumkan account reference peran yang dipakai (ROADMAP §9, §23).
- Kesepakatan dengan owner tentang data uji dan kemampuan roll-back sebelum menyentuh fungsi mutasi.

## Required Context

- Daftar fungsi privileged dari inventaris: endpoint, method, dan indikator fungsinya.
- Baseline request peran tinggi (admin) yang membuktikan fungsi bekerja.
- Credential reference peran rendah.
- Pemetaan fungsi read-only versus fungsi yang melakukan mutasi.

## Required Capabilities


- `request_replay` — memanggil ulang fungsi dengan identitas peran rendah di dalam approval.
- `response_comparison` — membandingkan respons admin versus peran rendah atas fungsi yang sama.

Skill tidak menentukan provider; replay hanya melalui provider proxy (ROADMAP §4.1, §5.2, §11).

## Required Credentials

- Pengujian menuntut akun peran rendah, idealnya juga peran tinggi untuk baseline, sehingga frontmatter menyatakan `requires_credentials: true`.
- Reference saja (`account-admin`, `account-user`); nilai dikelola credential provider dan di-inject saat eksekusi (ROADMAP §23).
- Jangan menyalin nilai kredensial ke konteks, evidence, atau report.
- Evidence dari request authenticated wajib tersanitasi otomatis sebelum dipersist (ROADMAP §23, §25).

## Core Concepts

- **Fungsi versus object**: BFLA menanyakan "bolehkah peran ini memanggil aksi ini"; BOLA menanyakan "bolehkah identitas ini melihat object ini".
- **Indikator fungsi**: endpoint manajemen, method stateful, kata kerja aksi di path, dan payload operasi massal.
- **Dampak lebih dulu**: memanggil fungsi admin bisa menciptakan atau menghancurkan state — pilih urutan uji dari yang efek sampingnya paling kecil.
- **Denial eksplisit**: penolakan yang benar biasanya 403/401 dengan body ringkas, bukan error generik.

## Reasoning Workflow

1. Inventarisasi fungsi privileged dari history; klasifikasikan read-only versus mutasi.
2. Kumpulkan baseline peran tinggi untuk satu fungsi pilihan yang paling aman (read-only atau idempotent).
3. Rumuskan hypothesis: "peran rendah dapat memanggil fungsi X".
4. Ajukan approval scoped; untuk fungsi mutasi, sertakan rencana mitigasi (data uji, lab, roll-back) di pengajuan.
5. Jalankan satu replay dengan identitas peran rendah — satu fungsi per iterasi.
6. Bandingkan respons baseline admin versus peran rendah; klasifikasikan denied, allowed, atau ambigu.
7. Jalankan false-positive check, perbarui status hypothesis, dan simpan evidence.

## Allowed Operations

- Replay satu fungsi per iterasi dengan budget kecil (satu digit request per fungsi).
- Prioritas fungsi read-only atau ber-efek-samping-minimal lebih dulu; fungsi mutasi hanya di lab atau data uji.
- Perbandingan respons dan dokumentasi hasil per fungsi.

## Approval Requirements

- Fungsi read-only: approval scoped standar (ROADMAP §9).
- Fungsi mutasi (POST/PUT/PATCH/DELETE): risk HIGH → approval eksplisit dan mitigasi dampak tercatat (ROADMAP §8).
- Approval menyebut account reference peran yang dipakai (ROADMAP §9, §23).

## Forbidden Operations

- Memanggil fungsi destruktif di produksi: hapus massal, reset kredensial user lain, atau ubah konfigurasi global.
- Mengiterasi seluruh katalog fungsi sekaligus — uji satu fungsi, bukan pemindaian.
- Memakai baseline admin untuk memodifikasi state demi memuluskan pengujian.
- Menyimpan keluaran fungsi sensitif (mis. dump daftar pengguna) lebih dari yang minimal, tanpa redaksi.

## Evidence Requirements

- Baseline admin dan replay peran rendah untuk fungsi yang sama, dengan account reference dan waktu.
- Klasifikasi denied/allowed dengan bukti body respons (ter-redact bila berisi data).
- Catatan mitigasi dampak yang disepakati owner untuk fungsi mutasi.
- Hash dan provenance tiap artifact (ROADMAP §25).

## False Positive Checks

- Respons 200 dengan body kosong atau template bukan bukti fungsi dijalankan.
- Error 500 bisa berarti fungsi gagal di tengah jalan — cek apakah efek samping tetap terjadi.
- Endpoint "admin" yang ternyata self-service untuk semua pengguna (by design).
- Middleware cache menyajikan respons admin ke sesi lain.

## Severity Guidance

- Peran rendah memanggil fungsi administratif lintas pengguna (buat/hapus akun, ekspor data): kritis hingga tinggi.
- Fungsi privileged berdampak terbatas (mis. melihat log sendiri): sedang.
- Fungsi yang terbuka tanpa sengaja namun tanpa dampak data: rendah.
- Severity mengikuti dampak fungsi, bukan kedengaran nama endpoint-nya.

## Stop Conditions

- Replay fungsi mutasi menunjukkan efek samping tak terduga → berhenti segera dan laporkan ke owner (ROADMAP §10).
- Peran rendah terkunci atau kehilangan akses → hentikan alur pengujian akun itu.
- Stop condition umum §10 terpicu → status hypothesis `inconclusive`.

## Output Format

- Temuan per fungsi: endpoint, method, klasifikasi akses, pasangan baseline-versus-replay, dan dampak potensial.
- Daftar fungsi yang belum diuji beserta alasannya (risiko dampak, tanpa baseline).
- Status lifecycle per hypothesis fungsi.

## Related Skills

- `idor-and-bola` — pasangan level-object; bedakan cakupan sebelum menulis temuan.
- `web-authorization` — kerangka matrix peran.
- `api-security-methodology` — peta rute pengujian API.
- `vulnerability-validation` — kontrak validasi umum.
