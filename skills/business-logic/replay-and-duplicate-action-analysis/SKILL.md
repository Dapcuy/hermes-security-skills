---
name: replay-and-duplicate-action-analysis
description: >
  Use when an action might not be protected against duplicate submission:
  resend an identical request with test accounts, check idempotency behavior,
  and look for double-execution indications such as double-spend, while
  recognizing deliberately designed idempotency keys as correct behavior.
version: 0.1.0
risk: medium
requires_credentials: true
---

# Replay And Duplicate Action Analysis

## Purpose

- Menguji apakah aksi tertentu terlindungi dari duplicate submission: request identik yang dikirim ulang tidak seharusnya dieksekusi dua kali.
- Memeriksa perilaku idempotency yang dinyatakan maupun tersirat, dan mengidentifikasi indikasi double-execution seperti double-spend atau entri ledger ganda.
- Membedakan proteksi yang memang didesain (idempotency key, unique constraint) dari kegagalan enforcement yang nyata.

## When To Use

- Form atau endpoint aksi (submit order, vote, redeem voucher, transfer) yang bisa dikirim ulang dari klien.
- Indikasi server tidak memiliki unique constraint, nonce, atau idempotency check pada aksi bernilai.
- Hypothesis double-spend: satu aksi mengurangi saldo/kuota dua kali.

## When Not To Use

- Authorization `pending` atau scope tidak mencakup endpoint aksi (ROADMAP §8).
- Aksi bersifat transaksi finansial nyata — alihkan ke transaction-analysis dengan approval STRICT.
- Pengujian butuh banyak request paralel — itu race-condition-analysis, bukan duplicate sederhana.
- Endpoint sudah terbukti memakai idempotency key dan perilakunya benar pada baseline — tidak ada hypothesis yang tersisa.

## Authorization Preconditions

- Authorization `granted` atau `offline-lab` dengan scope entry eksplisit untuk endpoint aksi yang diuji.
- Approval aktif untuk replay stateful (aksi umumnya POST) — budget mencakup minimal dua eksekusi identik per skenario (ROADMAP §8, §9).
- Test account dipakai melalui credential reference yang sah; aksi hanya terjadi pada objek milik test account sendiri (ROADMAP §23).
- Aksi yang memicu efek ke pihak ketiga (email, notifikasi, order nyata) hanya diuji di lab atau pada mode sandbox.

## Required Context

- Definisi aksi: endpoint, method, payload, dan efek state yang diharapkan (entri baru, saldo berkurang, kuota turun).
- Baseline: satu eksekusi sah beserta state sebelum/sesudahnya.
- Sinyal idempotency yang dinyatakan: header idempotency, request id, atau unique constraint yang diketahui.
- Cara membaca state akhir yang sah (endpoint status, respons aksi) untuk memverifikasi efek ganda.

## Required Capabilities

- `request_replay` — mengirim ulang request aksi yang identik sesuai approval, satu per satu, tanpa concurrency.
- Skill hanya meminta replay; penilaian efek ganda dilakukan sebagai analisis atas respons dan perbandingan state antar eksekusi.
- Provider ditentukan registry (ROADMAP §4.1, §5); replay aktif hanya melalui provider proxy (ROADMAP §5.2).

## Required Credentials

- Aksi diuji pada alur authenticated milik test account, sehingga frontmatter menyatakan `requires_credentials: true`.
- Hermes hanya melihat credential reference (mis. `account-a`), tidak pernah nilainya (ROADMAP §23).
- Control plane meng-inject kredensial saat eksekusi; jangan pernah menangani nilai kredensial di percakapan.
- Authorization kadaluarsa membuat credential reference terkait tidak lagi valid.

## Core Concepts

- **Duplicate submission**: request yang sama persis (payload, header, timestamp yang diperbolehkan) dikirim dua kali; server yang benar mengeksekusi efeknya tepat satu kali.
- **Idempotency by design**: mekanisme idempotency key yang mengembalikan respons sama dan tidak mengeksekusi ulang adalah perilaku benar — bukan bug, dan bukan temuan.
- **Double-spend indication**: efek bernilai tercatat dua kali (saldo berkurang dua kali, dua entri ledger, dua kuota terpakai) untuk satu niat aksi.
- **Replay satu-aksi**: aksi sekali-pakai (redeem, vote, klaim) yang bisa diputar ulang menandakan tidak ada konsumsi state.
- **Satu skenario, satu aksi**: tanpa concurrency dan tanpa variasi payload pada skenario duplikasi murni agar bukti bersih.

## Reasoning Workflow

1. Tetapkan aksi yang diuji, efek state yang diharapkan, dan cara membaca state akhir yang sah.
2. Rekam baseline: satu eksekusi sah beserta snapshot state sebelum/sesudah.
3. Ajukan approval replay stateful dengan budget minimal dua eksekusi per skenario.
4. Kirim ulang request identik pada kondisi yang setara; catat status, respons, dan state akhir.
5. Bandingkan: apakah efek terjadi sekali, dua kali, atau ditolak dengan pesan duplikasi? Untuk aksi sekali-pakai, apakah redeem kedua berhasil?
6. Jalankan FP check (terutama idempotency by design), lalu perbarui status hypothesis dan pastikan kondisi test account tercatat.

## Allowed Operations

- Pengiriman ulang request aksi identik dalam batas budget approval, tanpa concurrency.
- Pembacaan state akhir melalui endpoint yang dalam scope, dihitung dalam budget.
- Pengulangan skenario dengan request id/idempotency key yang baru untuk membedakan mekanisme proteksi, bila approval mencakupnya.

## Approval Requirements

- Aksi stateful (POST/PUT/PATCH) → risk HIGH → approval eksplisit wajib sebelum eksekusi (ROADMAP §8).
- Approval wajib scoped: capability, host, method, path, account reference, request budget, dan expiration (ROADMAP §9).
- Approval kadaluarsa dibuat ulang sebagai approval baru; pencabutan berarti berhenti di kondisi aman (ROADMAP §9, §10).

## Forbidden Operations

- Mengirim ulang aksi pada objek milik user lain atau di luar test account.
- Menggabungkan duplikasi dengan concurrency tanpa pindah ke race-condition-analysis dan approval HIGH-nya.
- Memaksa ratusan duplikat untuk "membuktikan" — dua sampel yang bersih cukup untuk indikasi; volume bukan bukti.
- Menyimpulkan double-spend tanpa membaca state akhir yang sah.
- Melanjutkan eksekusi setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Pasangan snapshot state sebelum/sesudah untuk baseline dan untuk tiap eksekusi ulang.
- Request ter-sanitasi yang identik beserta timestamp, status, dan respons tiap pengiriman.
- Bukti mekanisme proteksi (atau ketiadaannya): pesan duplikasi, header idempotency yang direspon, atau dua entri efek.
- Minimum set ROADMAP §25 untuk hypothesis yang naik status, termasuk FP analysis khusus idempotency.

## False Positive Checks

- **Idempotency by design**: apakah server memang didesain menerima ulang tapi hanya mengeksekusi sekali (respons sama, efek tunggal)? Itu bukan bug.
- Apakah duplikasi "berhasil" hanya menghasilkan entri draft yang tidak bernilai?
- Apakah efek kedua sebenarnya dibatalkan proses asinkron (reconciliation, cleanup job)?
- Apakah unique constraint bekerja di layer database dan pengujian gagal karena alasan lain (validasi klien)?
- Apakah dua entri efek berasal dari dua request yang tidak benar-benar identik (retry yang membawa request id berbeda)?

## Severity Guidance

- Double-spend pada nilai nyata (saldo, kuota berbayar, voucher) berada di rentang severity tinggi bila terbukti di state akhir.
- Duplikasi yang hanya menghasilkan noise data (entri ganda tanpa nilai) berada di rentang rendah-menengah.
- Idempotency key yang ada dan bekerja bukan temuan; jangan menaikkan severity dari mekanisme yang justru bekerja dengan benar.

## Stop Conditions

- Efek ganda teramati pada nilai yang bukan milik test account → stop segera dan laporkan (ROADMAP §10).
- Budget approval habis sebelum pasangan eksekusi lengkap → stop dan tandai `inconclusive`.
- Side effect tidak terduga (order nyata terkirim, notifikasi keluar) → stop segera.
- Authorization kadaluarsa, approval dicabut, policy menjadi deny, atau repeated 5xx → stop (ROADMAP §10).

## Output Format

- Duplicate-action record: aksi, skenario, jumlah eksekusi, hasil tiap eksekusi, snapshot state, dan status hypothesis baru.
- Kesimpulan idempotency: mekanisme yang teramati (key, constraint, none) dan apakah perilakunya sesuai desain.
- Referensi evidence (hash + path) untuk baseline, eksekusi ulang, dan snapshot state.

## Related Skills

- `transaction-analysis` — nilai finansial nyata dengan approval STRICT.
- `race-condition-analysis` — duplikasi pada jendela waktu dengan concurrency terkontrol.
- `workflow-state-analysis` — pelanggaran urutan langkah pada alur multi-step.
- `vulnerability-validation` — kerangka validasi umum dan status lifecycle.
- `false-positive-analysis` — penyisiran FP, terutama desain idempotency.
