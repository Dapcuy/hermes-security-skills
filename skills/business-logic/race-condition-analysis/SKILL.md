---
name: race-condition-analysis
description: >
  Use when a check-then-act window might be exploitable with concurrent
  requests: identify the window first, then run strictly limited concurrency
  only under explicit HIGH-risk approval, never automatically, and account
  for eventual consistency before calling it a finding.
version: 0.1.0
risk: high
---

# Race Condition Analysis

## Purpose

- Mengidentifikasi jendela check-then-act pada operasi bernilai (saldo, kuota, voucher, vote) dan mengujinya dengan concurrency terkontrol dan sangat terbatas.
- Menegakkan profil approval paling ketat: concurrency hanya berjalan dengan approval HIGH eksplisit — tidak pernah automatic (ROADMAP §8, §22).
- Memisahkan race condition nyata dari perilaku asinkron yang sah (eventual consistency, queue processing).

## When To Use

- Operasi menunjukkan pola check-then-act: validasi ketersediaan lalu penerapan efek, tanpa mekanisme lock yang terlihat.
- Indikasi nilai ganda pada jendela sempit: kuota terlewati, voucher terpakai dua kali, vote ganda.
- Environment lab atau test account tersedia dan pemilik target menyetujui pengujian concurrency.

## When Not To Use

- Belum ada approval HIGH eksplisit untuk concurrency — tanpa itu, skill ini tidak pernah mengeksekusi request paralel.
- Jendela belum teridentifikasi dari model atau observation — temukan jendelanya dulu secara pasif, jangan "menembak ke gelap".
- Target produksi yang rapuh atau alur transaksi finansial nyata non-sandbox — stop, bukan lanjut.
- Anomali masih bisa dijelaskan eventual consistency — selesaikan FP check dulu sebelum klaim.

## Authorization Preconditions

- Authorization `granted` atau `offline-lab` dengan scope entry eksplisit untuk endpoint yang diuji.
- Approval HIGH eksplisit yang menyatakan concurrency maksimum kecil, request budget, dan expiration (ROADMAP §8, §9); approval biasa tanpa angka concurrency tidak cukup.
- Nilai yang dipertaruhkan hanya milik test account; amount/kuota terkecil yang bermakna.
- Pemilik target sadar bahwa pengujian mengirim request paralel dalam jumlah kecil; keraguan berarti stop.

## Required Context

- Model operasi: antrian check (ketersediaan, saldo, kuota) dan efek (penerapan, pengurangan) beserta endpoint-nya.
- Baseline: eksekusi tunggal sah beserta state sebelum/sesudah.
- Sinyal lock yang diketahui: unique constraint, transaksi database, idempotency check, atau optimistic locking.
- Batas approval: concurrency maksimum, jumlah burst, dan total request.

## Required Capabilities

- `request_replay` — mengeksekusi burst kecil request identik secara paralel sesuai approval HIGH, lalu eksekusi tunggal untuk verifikasi state.
- Paralelisme hanya berarti beberapa replay dalam jendela waktu yang sangat berdekatan, dengan derajat kecil yang disetujui approval.
- Provider menentukan implementasi eksekusinya (ROADMAP §4.1, §5.2); analisis hasil dilakukan atas data replay, bukan operasi tambahan.

## Core Concepts

- **Jendela dulu, burst kemudian**: identifikasi window dari pola check-then-act dan respons yang menunjukkan validasi terpisah dari penerapan; burst hanya setelah jendela masuk akal.
- **Concurrency kecil dan eksplisit**: default ROADMAP §22 adalah satu request pada satu waktu; paralelisme apa pun adalah penyimpangan yang wajib dinyatakan approval dengan angka kecil (satu digit) dan terbatas.
- **Burst tunggal, bukan hammering**: satu burst terencana per skenario — tidak ada pengulangan burst tanpa rencana dan budget.
- **Verifikasi state akhir**: race hanya terbukti dari state akhir (dua efek tercatat), bukan dari respons cepat antar request.
- **Approval HIGH, tidak pernah automatic**: concurrency pada alur bernilai adalah kelas operasi yang paling dijaga dalam pack ini (ROADMAP §8).

## Reasoning Workflow

1. Petakan operasi yang dicurigai: apa yang dicek, apa yang diterapkan, dan di mana keduanya bisa terpisah.
2. Kumpulkan sinyal jendela secara pasif: respons yang validasi-nya terpisah dari efek, dokumentasi API, atau observation sebelumnya.
3. Rekam baseline eksekusi tunggal beserta snapshot state sebelum/sesudah.
4. Ajukan approval HIGH dengan angka concurrency kecil, jumlah request, dan expiry eksplisit; tanpa itu, berhenti di tahap rencana.
5. Jalankan satu burst kecil request identik pada jendela yang dipilih; catat semua respons dan timing relatif.
6. Verifikasi state akhir melalui pembacaan yang sah: berapa efek yang benar-benar tercatat?
7. Jalankan FP check (eventual consistency, queue, cache), perbarui status hypothesis, dan pastikan kondisi test account tercatat.

## Allowed Operations

- Satu burst kecil paralel per skenario, dengan derajat paralel dan jumlah request persis seperti approval.
- Eksekusi tunggal untuk baseline dan verifikasi state, dihitung dalam budget.
- Pembacaan state akhir melalui endpoint dalam scope.

## Approval Requirements

- approval_required — tidak pernah automatic: concurrency berada di kelas HIGH; setiap burst menunggu approval eksplisit manusia yang menyebut angka paralel, budget, dan expiry (ROADMAP §8, §9).
- Approval wajib scoped: capability, host, method, path, account reference, concurrency maksimum, request budget, dan expiration (ROADMAP §9).
- Approval kadaluarsa atau dicabut berarti berhenti mutlak; burst tambahan butuh approval baru, bukan interpretasi longgar (ROADMAP §9).
- Kombinasi dengan alur transaksi finansial menuntut standar transaction-analysis (approval STRICT) di atas standar skill ini — ambil yang paling ketat.

## Forbidden Operations

- Request paralel tanpa approval HIGH yang menyebut angka paralel secara eksplisit.
- Hammering: burst berulang, loop tanpa henti, atau jumlah request besar — satu burst terencana per skenario.
- Concurrency pada akun atau objek milik pihak lain.
- Mengklaim race condition hanya dari respons error unik (mis. dua 200) tanpa verifikasi state akhir.
- Melanjutkan setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Model jendela (check vs act) beserta sumber sinyalnya.
- Record burst: jumlah request, derajat paralel, timing relatif, dan respons per request.
- Snapshot state sebelum/sesudah burst yang membuktikan jumlah efek tercatat.
- Minimum set ROADMAP §25 untuk hypothesis yang naik status, termasuk FP analysis eventual consistency dan rekap budget.

## False Positive Checks

- **Eventual consistency**: apakah state akhir benar setelah proses asinkron selesai — sementara terlihat ganda, akhirnya terkoreksi?
- Apakah efek "ganda" sebenarnya dua entri yang memang dibuat terpisah oleh desain (mis. dua item order)?
- Apakah queue/batch processing menyebabkan respons terlihat paralel padahal eksekusinya serial?
- Apakah cache menyebabkan pembacaan state yang stale sehingga verifikasi menyesatkan?
- Apakah respons unik (dua 200) disebabkan retry di layer klien/proxy, bukan eksekusi ganda?

## Severity Guidance

- Race yang menghasilkan efek ganda pada nilai nyata (saldo, kuota berbayar, limit) berada di rentang severity tinggi bila state akhirnya membuktikan.
- Race yang hanya melanggar batas lembut (mis. nama ganda) berada di rentang rendah-menengah.
- Sifat timing-dependent menurunkan confidence dibanding bug deterministik — tuliskan eksplisit di finding, jangan menaikkan severity untuk mengimbanginya.

## Stop Conditions

- Side effect tidak terduga: efek muncul pada objek lain, nilai berpindah ke entitas lain, atau sistem menunjukkan degradasi → stop segera (ROADMAP §10).
- Latensi naik signifikan atau repeated 5xx saat/ setelah burst → stop; target mungkin tidak menangani beban kecil pun.
- Budget approval (request atau waktu expiry) habis → stop dan rangkum hasil.
- Authorization kadaluarsa, approval dicabut, policy menjadi deny → stop mutlak (ROADMAP §10).

## Output Format

- Race condition record: operasi, model jendela, parameter burst (paralel, jumlah, timing), hasil state akhir, dan status hypothesis baru.
- Penilaian FP: penjelasan eventual consistency/asinkron yang tersisa dan mengapa klaim tetap berdiri (atau tidak).
- Referensi evidence (hash + path) untuk baseline, record burst, dan snapshot state.

## Related Skills

- `transaction-analysis` — alur finansial dengan approval STRICT; ambil standar yang paling ketat.
- `replay-and-duplicate-action-analysis` — duplikasi serial tanpa concurrency.
- `behavioral-anomaly-analysis` — sinyal pasif jendela dari history.
- `vulnerability-validation` — kerangka validasi umum dan status lifecycle.
- `false-positive-analysis` — penyisiran FP, terutama eventual consistency.
