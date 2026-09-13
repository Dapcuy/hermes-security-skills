---
name: engagement-scoping
description: >
  Use when a new target, program, or engagement is introduced: documenting
  the target, recording the authorization state (pending, granted,
  offline-lab), and writing explicit scope entries before any other
  security skill runs.
version: 0.1.0
risk: low
---

# Engagement Scoping

## Purpose

- Menjadi fondasi setiap engagement: mendokumentasikan target, status authorization, dan batasan scope secara eksplisit sebelum skill lain berjalan.
- Memastikan URL atau nama target yang diberikan user tidak pernah diperlakukan sebagai authorization otomatis (ROADMAP §8).
- Menghasilkan scope entries yang bisa divalidasi policy layer sebelum eksekusi dan saat eksekusi (TOCTOU guard, ROADMAP §4.2, §8).
- Menyimpan keputusan scoping sebagai case memory yang bisa diaudit belakangan.

## When To Use

- User memperkenalkan target, program bug bounty, atau lab baru.
- Engagement baru dimulai — urutan prioritas MVP (ROADMAP §45) menempatkan skill ini sebagai langkah pertama tanpa kecuali.
- Status authorization atau scope berubah di tengah engagement.
- User memberikan daftar host, API, atau aset tambahan yang belum tercatat.

## When Not To Use

- Bukan untuk mengeksekusi pengujian — skill ini tidak meminta capability aktif dan tidak menyentuh target.
- Bukan pengganti policy engine: validasi teknis scope (hostname, port, redirect, DNS resolution, private IP, cloud metadata endpoint) tetap tugas control plane, bukan reasoning model (ROADMAP §8).
- Bila engagement sudah lengkap terdokumentasi dan yang dibutuhkan hanya memilih teknik, lanjutkan ke security-task-routing.

## Authorization Preconditions

- Tidak ada operasi jaringan pada skill ini, sehingga tidak ada precondition aktif.
- Status authorization wajib terekam sebagai salah satu dari: `pending`, `granted`, `offline-lab`; `pending` adalah default.
- Active testing hanya boleh dipertimbangkan saat status `granted` atau `offline-lab`; selain itu semua jalur aktif berhenti (ROADMAP §8).
- Bukti authorization (pesan program, dashboard, perjanjian) wajib dicatat sebagai referensi — bukan diasumsikan.

## Required Context

- Identitas engagement (case id) dan sumber permintaan user.
- Daftar target yang disebut user: host, API, IP, aplikasi, atau lab.
- Syarat program bila ada: batasan method, larangan teknik, kebijakan disclosure, expiration authorization.
- Status authorization saat ini beserta sumber buktinya.

## Required Capabilities

Tidak ada capability aktif yang dibutuhkan skill ini. Seluruh pekerjaan berupa reasoning dan dokumentasi di sisi Hermes, tanpa menyentuh target. Bila engagement kelak butuh verifikasi otomatis, kebutuhan itu datang dari skill lain — bukan dari sini. Prinsipnya tetap: skill meminta capability, bukan tool (ROADMAP §4.1).

## Core Concepts

- **Authorization state**: `pending` (default), `granted`, `offline-lab`; status yang tidak jelas diperlakukan sama dengan `pending`.
- **Scope entry**: satu entri eksplisit berisi host, port, path, dan pengecualian; scope wildcard tidak pernah diasumsikan tanpa tertulis di terms.
- **Out-of-scope entry**: daftar eksplisit yang tidak boleh disentuh, termasuk third-party destination dan cloud metadata endpoint.
- **Engagement boundary**: semua skill lain merujuk hasil scoping ini sebelum operasi apapun; URL dari user bukan authorization.

## Reasoning Workflow

1. Catat identitas engagement dan permintaan awal user.
2. Ekstrak daftar target dan syarat program dari materi yang diberikan user.
3. Rekam status authorization beserta buktinya: siapa, kapan, lewat kanal apa, sampai kapan berlaku.
4. Pecah target menjadi scope entries eksplisit; tulis out-of-scope entries di sampingnya.
5. Simpan ringkasan scoping ke case memory sebagai dokumen acuan engagement.
6. Tegaskan ke skill berikutnya: tanpa status `granted`/`offline-lab`, hanya jalur pasif yang boleh berjalan.

## Allowed Operations

- Membaca materi dari user: URL program, terms, daftar target, catatan engagement.
- Menulis case memory: scope entries, authorization record, dan catatan keputusan scoping.
- Reasoning dan dokumentasi lokal — tanpa operasi jaringan.

## Approval Requirements

- Tidak ada operasi yang memerlukan approval karena skill ini tidak melakukan operasi aktif.
- Perubahan status authorization ke `granted` wajib didasarkan bukti nyata dari user; bila ragu, status tetap `pending`.
- Perubahan scope di tengah engagement wajib dicatat sebagai entri baru dengan sumber, agar policy layer bisa mengevaluasi ulang execution plan yang berjalan (ROADMAP §8).

## Forbidden Operations

- Menganggap URL, kredensial akses, atau invite program sebagai authorization.
- Mengubah scope atau status authorization tanpa sumber yang bisa ditunjuk.
- Memulai pengujian, scanning, atau replay dari skill ini.
- Menambahkan target yang tidak disebut user maupun program terms.

## Evidence Requirements

- Authorization record mencantumkan: status, sumber bukti, waktu pencatatan, dan masa berlaku.
- Setiap scope entry punya alasan atau sumber: dari program terms atau pernyataan eksplisit user.
- Perubahan scope/status dicatat sebagai entri baru yang menambah riwayat, bukan menimpa riwayat lama.

## False Positive Checks

- Host yang reachable bukan berarti in-scope — jangan menyimpulkan scope dari hasil koneksi.
- Wildcard scope (mis. `*.example.com`) hanya berlaku bila tertulis eksplisit di terms, dan tetap menghormati out-of-scope entries.
- Lab lokal yang aktif bukan berarti target produksi ikut ter-authorized; environment harus tercatat terpisah.

## Severity Guidance

- Skill ini tidak menghasilkan finding, sehingga tidak menetapkan severity.
- Kesalahan scoping bersifat fatal bagi engagement: satu target out-of-scope yang terlewat membuat seluruh temuan berikutnya tidak sah.
- Prioritaskan ketelitian di atas kecepatan; scope yang ragu-ragu lebih baik ditandai `pending`.

## Stop Conditions

- Authorization tidak bisa dipastikan → berhenti sebelum skill lain dimuat (ROADMAP §10).
- Scope ambigu atau bertentangan dengan program terms → minta klarifikasi user; jangan menebak.
- User menolak atau gagal memberi dasar authorization → nyatakan engagement tidak bisa dilanjutkan secara aktif.

## Output Format

- Ringkasan engagement terstruktur: case id, target, authorization state, scope entries, out-of-scope entries, dan batasan khusus.
- Status per target: siapa yang boleh diuji, dengan cara apa, dan kapan authorization kadaluarsa.
- Daftar pertanyaan tersisa untuk user bila ada bagian yang belum bisa didokumentasikan.

## Related Skills

- `security-task-routing` — memilih jalur analisis setelah scoping selesai.
- `evidence-handling` — menyimpan authorization record dan scope entries sebagai evidence berkaidah.
- Semua skill Tier 2 ke atas — seluruhnya bergantung pada hasil scoping ini.
