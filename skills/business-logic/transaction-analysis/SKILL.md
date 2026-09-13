---
name: transaction-analysis
description: >
  Use when a hypothesis touches real financial or value-bearing transactions
  (payments, balances, refunds, credits): strict explicit approval, minimal
  request budget, smallest possible amounts, no destructive testing, and
  hard stop conditions before anything is executed.
version: 0.1.0
risk: high
---

# Transaction Analysis

## Purpose

- Memvalidasi hypothesis pada alur transaksi finansial atau bernilai nyata (pembayaran, saldo, refund, kredit, debit) dengan penahanan risiko maksimum.
- Menegakkan profil eksekusi paling konservatif di seluruh skill pack: approval STRICT, budget minimal, amount terkecil, tanpa destructive testing (ROADMAP §8, §10).
- Menghasilkan bukti dampak yang bisa diaudit tanpa mengubah nilai finansial di luar test environment yang disetujui.

## When To Use

- Hypothesis menyentuh alur uang atau nilai: saldo bisa berubah melebihi seharusnya, refund ganda, diskon ditumpuk, atau nilai transaksi bisa dimanipulasi.
- Environment sandbox atau test store tersedia dan dinyatakan sah oleh pemilik target.
- Perpindahan nilai hanya terjadi antar test account yang dikendalikan engagement.

## When Not To Use

- Environment produksi tanpa sandbox, atau transaksi menyangkut dana nyata pihak ketiga — jangan dieksekusi; argumentasikan dampaknya saja.
- Authorization dan approval STRICT belum lengkap — tidak ada eksekusi parsial.
- Hypothesis masih kasar dan belum dimodelkan — model dulu di business-logic-methodology.
- Alternatif pembuktian non-transaksional tersedia (mis. membaca validasi sisi klien) yang menjawab hypothesis dengan risk lebih rendah.

## Authorization Preconditions

- Authorization `granted` atau `offline-lab` dengan scope entry eksplisit untuk seluruh endpoint transaksi yang disentuh.
- Approval STRICT yang eksplisit — lihat Approval Requirements; tanpa approval semacam itu, skill ini tidak pernah mengeksekusi apa pun.
- Nilai transaksi dibatasi ke amount terkecil yang bermakna dan hanya antar test account; currency atau mode sandbox digunakan bila tersedia.
- Pemilik target menyadari bahwa pengujian menyentuh alur transaksi; keraguan berarti stop, bukan lanjut.

## Required Context

- Model alur transaksi: endpoint, parameter nilai (amount, kuantitas, diskon), urutan, dan state akhir (saldo, status order).
- Baseline transaksi sah pada test account: request, respons, dan state sebelum/sesudah.
- Batas eksplisit dari approval: jumlah request maksimum, amount maksimum per request, dan total nilai yang boleh berpindah.
- Daftar test account (credential reference) dan kondisi awal saldonya.

## Required Capabilities

- `request_replay` — mengeksekusi request transaksi terkendali sesuai approval STRICT, satu per satu, tanpa concurrency.
- Eksekusi hanya lewat provider proxy sesuai registry (ROADMAP §4.1, §5.2); tidak ada jalur lain ke target.
- Verifikasi state akhir dilakukan sebagai analisis atas respons dan baseline, bukan operasi aktif tambahan di luar budget.

## Core Concepts

- **Approval STRICT, bukan conditional**: alur uang diperlakukan sebagai HIGH sejak awal; tidak ada eksekusi tanpa approval eksplisit yang menyebut batas nilai.
- **Budget minimal**: jumlah request, amount per request, dan total nilai berpindah dibatasi serendah yang masih bisa menjawab hypothesis.
- **Tanpa destructive testing**: tidak ada aksi yang menghapus, membatalkan milik orang lain, atau mengubah data finansial di luar test account (ROADMAP §2, §10).
- **Bukti state, bukan klaim**: setiap klaim "saldo berubah melebihi seharusnya" wajib disertai snapshot state sebelum dan sesudah.
- **One-shot preference**: satu iterasi yang dirancang baik lebih berharga daripada deretan percobaan pada alur uang.

## Reasoning Workflow

1. Tuliskan prediksi dampak: state apa yang berubah, berapa besar, dan mengapa itu melanggar aturan bisnis.
2. Tentukan skenario eksekusi paling ringan yang menjawab hypothesis dan batas nilai terkecilnya.
3. Rekam baseline transaksi sah pada test account (satu kali, dalam approval).
4. Jalankan satu skenario terkendali sesuai approval; catat request, respons, dan snapshot state sebelum/sesudah.
5. Verifikasi state akhir melalui respons yang sah (bukan manipulasi tambahan); hentikan segera bila ada sinyal aneh.
6. Jalankan FP check (pembulatan, konversi mata uang, state pending), lalu perbarui status hypothesis dan pulihkan kondisi test account bila perlu.

## Allowed Operations

- Satu request transaksi terkendali per skenario, dengan amount terkecil yang bermakna, dalam batas approval STRICT.
- Pembacaan state (saldo, status order) melalui endpoint yang sudah dalam scope, dihitung dalam budget.
- Pemulihan kondisi test account melalui alur normal yang disetujui, bila approval mencakupnya.

## Approval Requirements

- approval_required — tidak pernah automatic: semua eksekusi transaksi menunggu approval eksplisit dari manusia, tanpa pengecualian dan tanpa jalur otomatis (ROADMAP §8).
- Approval wajib scoped dan menyebut: capability, host, method, path, account reference, request budget, amount maksimum per request, total nilai maksimum, dan expiration (ROADMAP §9).
- Approval kadaluarsa atau dicabut berarti berhenti mutlak; renewal dibuat sebagai approval baru dengan audit trail terpisah (ROADMAP §9).
- Perubahan di tengah jalan (amount lebih besar, request tambahan) = approval baru, bukan interpretasi longgar atas approval lama.

## Forbidden Operations

- Eksekusi transaksi tanpa approval STRICT yang aktif, atau melampaui amount/total nilai yang disetujui.
- Destructive testing: menghapus/membatalkan data milik user lain, mengosongkan saldo, memicu refund massal (ROADMAP §2, §10).
- Concurrency pada alur transaksi — itu wilayah race-condition-analysis dengan approvalnya sendiri; jangan digabung diam-diam.
- Mengeksekusi pada akun nyata non-test atau menyeret nilai ke pihak ketiga.
- Melanjutkan eksekusi setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Snapshot state sebelum dan sesudah setiap skenario (saldo, status), sebagai pasangan yang bisa dibandingkan auditor.
- Request/response ter-sanitasi per skenario, beserta amount dan timestamp.
- Rekap total nilai yang berpindah selama pengujian versus batas approval — wajib nol kelebihan.
- Minimum set ROADMAP §25 untuk hypothesis yang naik status, termasuk FP analysis dan scope reference.

## False Positive Checks

- Apakah selisih saldo disebabkan pembulatan, konversi mata uang, atau biaya administrasi yang memang didesain?
- Apakah state masih pending dan akan dikoreksi proses asinkron (settlement, reconciliation)?
- Apakah respons sukses hanyalah kalkulasi sisi klien tanpa perubahan state server?
- Apakah snapshot "sebelum" sudah outdated sehingga selisihnya ilusi?

## Severity Guidance

- Dampak finansial yang terbukti pada test environment dinilai terhadap kelayakan di produksi; jangan menaikkan severity hanya karena angkanya terlihat besar.
- Manipulasi nilai yang butuh kondisi tidak realistis diturunkan severity-nya atau dianggap `inconclusive`.
- Kerugian langsung yang bisa direproduksi (double credit, refund ganda) berada di rentang severity tinggi — dengan syarat evidence pasangan state lengkap.

## Stop Conditions

- Side effect tidak terduga: saldo berubah di luar skenario, transaksi muncul yang tidak diminta, atau nilai berpindah ke entitas lain → stop segera dan laporkan (ROADMAP §10).
- Approval habis (jumlah request, amount, atau total nilai) → stop mutlak.
- Target tidak sehat (repeated 5xx, timeout pada alur pembayaran) → stop; alur uang pada sistem tidak stabil adalah bahaya.
- Authorization kadaluarsa, approval dicabut, policy menjadi deny, atau keraguan apa pun muncul → stop (ROADMAP §10).

## Output Format

- Transaction validation record: hypothesis id, skenario yang dijalankan, snapshot state sebelum/sesudah, budget dan nilai terpakai, status hypothesis baru.
- Pernyataan dampak: berapa dan nilai apa yang bisa berpindah melebihi seharusnya, beserta batas kondisinya.
- Referensi evidence (hash + path) untuk baseline, tiap skenario, dan snapshot state.

## Related Skills

- `business-logic-methodology` — peta routing dan pemodelan alur bisnis.
- `race-condition-analysis` — concurrency pada alur bernilai, dengan approval tersendiri.
- `replay-and-duplicate-action-analysis` — duplikasi aksi dan indikasi double-spend.
- `vulnerability-validation` — kerangka validasi umum dan status lifecycle.
- `false-positive-analysis` — penyisiran FP sebelum status naik.
