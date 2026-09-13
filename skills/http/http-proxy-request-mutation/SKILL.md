---
name: http-proxy-request-mutation
description: >
  Use when a recorded request needs controlled modification before replay:
  planning one-variable-at-a-time mutations of parameters, headers, or body
  fields, documenting every change, and keeping each iteration comparable.
version: 0.1.0
risk: medium
---

# HTTP Proxy Request Mutation

## Purpose

- Metodologi mutasi terkontrol atas request terekam sebelum replay: parameter, header, atau body field — satu variabel per iterasi.
- Menjamin setiap mutasi terencana, terdokumentasi, dan menghasilkan perbandingan yang bermakna terhadap baseline.
- Menjaga mutasi tetap di dalam approval, budget, dan larangan payload project (ROADMAP §8, §22).

## When To Use

- Hypothesis membutuhkan variasi input: nilai parameter berbeda, header tambahan, atau field body baru.
- Uji mass assignment: menambah satu field pada body untuk melihat apakah server menerimanya.
- Iterasi validasi yang menuntut diskriminan — hanya satu hal yang berubah antar request.

## When Not To Use

- Tanpa baseline request yang bersih — mutasi tanpa pembanding tidak menghasilkan kesimpulan.
- Mutasi berpola payload attack (injection, exfiltration, credential) di luar jalur kurasi — payload memasuki eksekusi hanya lewat payload-selection dan controlled-fuzzing (ROADMAP §22).
- Tanpa approval untuk mutasi yang menyentuh method stateful.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; approval scoped mencakup bentuk request hasil mutasi: host, method, path, account reference bila perlu, budget, dan expiry (ROADMAP §9).
- TOCTOU: scope direvalidasi saat eksekusi — mutasi yang membawa request keluar scope ditolak di jalur proxy (ROADMAP §4.2, §11).
- Nilai pengganti berasal dari payload set terkurasi dengan metadata lengkap (ROADMAP §22).

## Required Context

- Baseline request/response yang bersih.
- Mutation plan: daftar mutasi kandidat beserta hypothesis yang diuji tiap mutasi.
- Payload set terkurasi bila mutasinya mengganti nilai (dari payload-selection).
- Approval aktif dan sisa budget.

## Required Capabilities

- `request_replay` — mengeksekusi request hasil mutasi melalui provider proxy, satu mutasi per iterasi.

Skill tidak menentukan provider (ROADMAP §4.1). Perbandingan hasil mutasi terhadap baseline diminta ke skill response comparison, bukan di sini.

## Core Concepts

- **Satu variabel per iterasi**: perbedaan respons hanya bisa diatribusikan bila penyebabnya tunggal.
- **Mutation plan tertulis**: mutasi yang tidak tercatat adalah iterasi terbuang; tiap mutasi punya alasan dan hypothesis asal.
- **Kelas mutasi**: ganti nilai parameter; tambah/hapus header; tambah/ubah field body; ganti method — kelas tertinggi, selalu dengan approval HIGH.
- **Payload lewat pintu kurasi**: nilai pengganti dari payload set ber-metadata, bukan string improvisasi (ROADMAP §22).

## Reasoning Workflow

1. Kunci baseline: request dan respons bersih dari iterasi sebelumnya.
2. Tulis mutation plan: urutan mutasi kecil (satu digit) dengan hypothesis per mutasi dan estimasi budget.
3. Eksekusi satu mutasi: ubah tepat satu elemen, replay, dan catat mutasi persisnya — elemen, nilai lama, dan kelas nilai baru.
4. Bandingkan respons terhadap baseline lewat skill response comparison; klasifikasikan perubahan: relevan dengan hypothesis atau noise.
5. Putuskan iterasi berikutnya: kembali ke baseline (revert) sebelum mutasi berikutnya, atau lanjut dari state terbaru bila hypothesis menuntut — nyatakan pilihan ini eksplisit.
6. Tutup siklus: ringkasan mutasi yang dijalankan, yang disisihkan, dan hasilnya per hypothesis.

## Allowed Operations

- Mutasi kecil terdokumentasi di dalam budget approval; satu replay per mutasi; jeda antar request sesuai rate limit (ROADMAP §22).
- Mutasi method stateful hanya dengan approval HIGH dan mitigasi dampak (ROADMAP §8).
- Revert ke baseline antar iterasi untuk menjaga keterbandingan.

## Approval Requirements

- Approval scoped mencakup bentuk akhir request bermutasi; mutasi yang membawa request keluar dari bentuk yang disetujui ditolak policy (ROADMAP §9, §11).
- Method stateful berstatus HIGH (ROADMAP §8).
- Menambah iterasi melebihi budget butuh approval baru — bukan penambahan diam-diam (ROADMAP §9).

## Forbidden Operations

- Mengubah beberapa variabel sekaligus sehingga perbandingan tidak bermakna.
- Menyuntikkan payload tanpa metadata atau dari luar payload set terkurasi (ROADMAP §22).
- Mutasi destruktif, exfiltration, atau credential attack — kategoris dilarang (ROADMAP §2, §22).
- Melanjutkan iterasi setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Mutation log per iterasi: elemen yang diubah, nilai lama, kelas nilai baru, hypothesis yang diuji, replay id, dan hasil.
- Baseline yang dipakai sebagai acuan tiap perbandingan.
- Budget terpakai versus yang disetujui.
- Artifact ter-hash dengan provenance (ROADMAP §25).

## False Positive Checks

- Perubahan respons bisa berasal dari sisa state iterasi sebelumnya — verifikasi revert bila dipakai.
- Content dinamis (timestamp, nonce, id sesi) menghasilkan diff kosmetik — bedakan dari diff substantif.
- Server bisa menormalisasi atau mengabaikan mutasi diam-diam — respons identik berarti mutasi tidak efektif, bukan hypothesis terbantahkan.
- Cache bisa menyajikan respons lama untuk request yang berbeda tipis.

## Severity Guidance

- Mutasi tidak menetapkan severity; hasil mutasi adalah observation untuk skill validasi.
- Mutasi yang "berhasil" (server menerima input) belum berarti vulnerability — dampak yang menentukan (ROADMAP §22).

## Stop Conditions

- Stop condition umum §10 terpicu: budget habis, rate limit, repeated 5xx, side effect tak terduga, approval dicabut, dsb.
- Mutation plan habis tanpa hasil diskriminan → tutup sebagai inconclusive, jangan berimprovisasi di luar rencana.
- Respons menunjukkan efek samping nyata pada data → berhenti dan laporkan (ROADMAP §10).

## Output Format

- Mutation log lengkap per iterasi dengan klasifikasi hasilnya.
- Ringkasan per hypothesis: didukung, terbantahkan, atau inconclusive.
- Referensi evidence (hash + path) dan catatan budget.

## Related Skills

- `http-proxy-request-replay` — eksekusi dasar yang dimutasi.
- `payload-selection` — pemasok nilai pengganti terkurasi.
- `http-proxy-response-comparison` — pembanding tiap iterasi.
- `vulnerability-validation` — kontrak validasi induk.
