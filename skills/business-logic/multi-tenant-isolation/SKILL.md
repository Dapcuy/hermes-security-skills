---
name: multi-tenant-isolation
description: >
  Use when tenant boundary enforcement must be tested: cross-tenant access
  attempts between dedicated test accounts of different tenants, judged with
  response comparison and carefully separated from shared reference data
  that is cross-tenant by design.
version: 0.1.0
risk: medium
requires_credentials: true
---

# Multi Tenant Isolation

## Purpose

- Menguji tegaknya batas tenant: apakah akun tenant A dapat membaca atau menulis objek milik tenant B melalui identifier yang bisa ditebak.
- Menilai hasil dengan perbandingan respons antar tenant, memisahkan kebocoran nyata dari data referensi bersama yang memang lintas tenant by design.
- Menjaga setiap percobaan akses lintas tenant di dalam scope, budget, dan approval yang berlaku, hanya pada test account yang dikendalikan.

## When To Use

- Aplikasi multi-tenant (workspace, organisasi, store) dengan objek yang diasosiasikan ke tenant dan identifier terlihat di URL/payload.
- Observation menunjukkan identifier lintas tenant diterima endpoint tanpa penolakan yang jelas.
- Perlu dibuktikan bahwa otorisasi tenant ditegakkan di server, bukan hanya disembunyikan di UI.

## When Not To Use

- Tidak tersedia test account pada dua tenant berbeda yang sah — jangan menguji dengan akun/objek milik orang lain.
- Authorization `pending` atau scope tidak mencakup endpoint yang diuji (ROADMAP §8).
- Hypothesis berhenti pada level object-level authorization generik tanpa konteks tenant — pertimbangkan idor-and-bola terlebih dahulu.
- Percobaan membutuhkan write lintas tenant pada data produksi nyata — hentikan; argumentasikan dampaknya saja.

## Authorization Preconditions

- Authorization `granted` atau `offline-lab` dengan scope entry eksplisit untuk endpoint yang diuji.
- Approval aktif untuk replay lintas konteks akun: host, method, path, kedua account reference, budget, dan expiration (ROADMAP §9).
- Kedua tenant yang diuji adalah test account milik engagement, dirujuk sebagai credential reference — tidak ada nilai kredensial di konteks (ROADMAP §23).
- Percobaan write lintas tenant ber-risk HIGH dan menuntut approval eksplisit tersendiri (ROADMAP §8).

## Required Context

- Model tenancy: bagaimana tenant diasosiasikan ke objek (field tenant id, subdomain, path) dan identifier mana yang terlihat.
- Test account pada minimal dua tenant berbeda, beserta objek milik masing-masing sebagai target acuan.
- Baseline respons dalam-tenant: akses sah akun ke objeknya sendiri.
- Daftar data yang diketahui bersama lintas tenant (katalog publik, master data) untuk memisahkan FP.

## Required Capabilities

- `request_replay` — mengeksekusi percobaan akses lintas tenant dengan konteks kredensial tenant sumber terhadap identifier tenant tujuan.
- `response_comparison` — membandingkan respons dalam-tenant versus lintas-tenant untuk mendeteksi perbedaan yang bermakna.
- Provider ditentukan capability registry (ROADMAP §4.1, §5); replay aktif hanya melalui provider proxy (ROADMAP §5.2).
- Verifikasi atribut objek dilakukan sebagai analisis atas data replay dan baseline, bukan operasi aktif tambahan di luar budget.

## Required Credentials

- Pengujian menuntut minimal dua akun pada tenant berbeda, sehingga frontmatter menyatakan `requires_credentials: true`.
- Hermes hanya melihat credential reference per tenant (mis. `tenant-a-account`, `tenant-b-account`), tidak pernah nilainya (ROADMAP §23).
- Control plane meng-inject kredensial sesuai konteks tenant saat eksekusi; jangan pernah meminta nilai kredensial ditempel ke percakapan.
- Authorization kadaluarsa membuat seluruh credential reference terkait tidak lagi valid.

## Core Concepts

- **Boundary dua arah**: uji read lintas tenant lebih dulu (lebih aman), write lintas tenant hanya dengan approval eksplisit karena dampaknya nyata.
- **Baseline dalam-tenant wajib**: respons sah ke objek sendiri adalah pembanding; tanpa itu, "berhasil" lintas tenant tidak bisa ditafsirkan.
- **Identifier vs authorization**: menerima identifier bukan kebocoran; yang dinilai adalah apakah data objek benar-benar dikembalikan/diubah.
- **Shared reference data**: katalog umum, konfigurasi global, dan master data memang lintas tenant — keberadaannya bukan temuan (FP klasik).
- **Konteks tenant di banyak tempat**: batas bisa dilanggar lewat path, query, body, header, atau subdomain — modelkan mana yang relevan sebelum menguji.

## Reasoning Workflow

1. Petakan objek per tenant dan identifier-nya; pilih pasangan objek acuan (milik tenant A, milik tenant B) yang aman diuji.
2. Rekam baseline dalam-tenant untuk kedua akun: akses sah ke objek masing-masing.
3. Ajukan approval untuk replay read lintas tenant dengan kedua account reference.
4. Eksekusi percobaan read lintas tenant: akun A meminta objek B; bandingkan responsnya dengan baseline dalam-tenant.
5. Klasifikasikan hasil: data objek B dikembalikan (indikasi kebocoran), ditolak dengan pesan izin, atau 404 yang tidak bisa dibedakan — gunakan response comparison untuk melihat perbedaannya.
6. Untuk write lintas tenant, ajukan approval HIGH tersendiri dan uji hanya pada objek test account dengan efek terkecil.
7. Jalankan FP check (terutama shared reference data), perbarui status hypothesis, dan catat kondisi kedua tenant.

## Allowed Operations

- Percobaan read lintas tenant antar test account dalam budget approval.
- Percobaan write lintas tenant pada objek test account dengan approval HIGH eksplisit dan efek terkecil.
- Pembacaan metadata objek melalui endpoint dalam scope untuk verifikasi atribut tenant.

## Approval Requirements

- Replay read lintas tenant ber-risk MEDIUM → approval conditional; percobaan write lintas tenant adalah HIGH → approval eksplisit wajib (ROADMAP §8).
- Approval wajib scoped dan menyebut kedua account reference: capability, host, method, path, budget, dan expiration (ROADMAP §9).
- Approval kadaluarsa dibuat ulang sebagai approval baru; pencabutan berarti berhenti segera (ROADMAP §9, §10).

## Forbidden Operations

- Mengakses objek tenant nyata di luar test account yang disediakan engagement.
- Menghapus atau merusak data lintas tenant dalam kondisi apa pun — destructive testing dilarang (ROADMAP §2, §10).
- Enumerasi massal identifier lintas tenant; gunakan pasangan objek acuan yang diketahui.
- Menyimpulkan kebocoran dari status code saja (404 vs 403) tanpa memeriksa isi respons.
- Melanjutkan eksekusi setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Pasangan baseline dalam-tenant dan percobaan lintas-tenant per objek acuan, dengan respons ter-sanitasi.
- Verifikasi atribut: bukti bahwa data yang dikembalikan benar milik tenant tujuan (field tenant, konten khas), bukan kemiripan.
- Untuk write: snapshot state sebelum/sesudah pada objek test account.
- Minimum set ROADMAP §25 untuk hypothesis yang naik status, termasuk FP analysis shared reference data dan scope reference.

## False Positive Checks

- **Shared reference data**: apakah objek yang "terakses" memang data global yang dibaca semua tenant by design?
- Apakah respons lintas tenant sebenarnya halaman error/redirect yang kebetulan 200?
- Apakah identifier tujuan sudah tidak ada sehingga 404 — bukan isolasi yang kuat maupun bocor?
- Apakah cache menyajikan data tenant A ke tenant B — jika ya, itu temuan tersendiri (cache deception), pisahkan dari isolasi aplikasi?
- Apakah atribut tenant diverifikasi dari isi data, bukan hanya dari asumsi identifier?

## Severity Guidance

- Kebocoran data bisnis lintas tenant (pesanan, pelanggan, dokumen) berada di rentang severity tinggi bila terbukti dengan verifikasi atribut.
- Kebocoran data referensi yang tidak sensitif berada di rentang rendah, dan sering bukan temuan sama sekali.
- Write lintas tenant yang terbukti dinilai lebih tinggi dari read pada pasangan objek yang setara — dampak integritas melebihi kerahasiaan parsial.

## Stop Conditions

- Data tenant nyata (bukan test account) muncul dalam respons → stop segera, sanitasi, dan laporkan (ROADMAP §10).
- Side effect tidak terduga pada tenant tujuan → stop dan catat kondisi.
- Budget habis, authorization kadaluarsa, approval dicabut, atau policy menjadi deny → stop (ROADMAP §10).
- Repeated 5xx atau indikasi target tidak sehat → stop; pengujian batas pada sistem tidak stabil menyesatkan.

## Output Format

- Isolation record: pasangan tenant/objek acuan, hasil tiap percobaan (read/write), verifikasi atribut, dan status hypothesis baru.
- Peta batas: endpoint yang menegakkan isolasi, yang ambigu, dan yang mengindikasikan kebocoran — beserta FP yang tersisa.
- Referensi evidence (hash + path) untuk baseline dan tiap percobaan.

## Related Skills

- `idor-and-bola` — kerangka object-level authorization yang lebih generik.
- `business-logic-methodology` — peta routing hypothesis business logic.
- `behavioral-anomaly-analysis` — sinyal pasif pola lintas tenant dari history.
- `vulnerability-validation` — kerangka validasi umum dan status lifecycle.
- `false-positive-analysis` — penyisiran FP, terutama shared reference data.
