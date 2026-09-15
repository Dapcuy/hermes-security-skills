---
name: redirect-analysis
description: >
  Use when mapping and analyzing HTTP redirects from recorded traffic:
  open redirect candidates in URL parameters (next, returnTo, url),
  redirect chain mapping, and validation bypass patterns — with the
  no-follow default enforced and every followed hop re-validated.
version: 0.1.0
risk: low
---

# Redirect Analysis

## Purpose

- Memetakan rantai redirect dari traffic terekam: hop, status code (301, 302, 303, 307, 308), dan tujuan efektif tiap hop.
- Mengidentifikasi kandidat open redirect: parameter yang menerima URL/path tujuan (next, returnTo, url, redirect, continue, dan variasinya) tanpa validasi yang terlihat.
- Menilai pola validasi tujuan redirect dan pola bypass yang lazim: allowlist longgar, prefix match, encoding, dan scheme terbuka.
- Menegaskan aturan pipeline: redirect no-follow secara default, dan tiap hop yang diikuti direvalidasi terhadap scope (ROADMAP §29).

## When To Use

- History memuat respons 3xx dan rantai redirectnya perlu dipahami sebelum analisis lanjutan.
- Parameter request berisi URL absolut atau path dan perlu dinilai apakah tujuannya bisa dialihkan ke domain luar.
- Dugaan open redirect muncul dari chain yang menunjuk domain tak dikenal atau dari review parameter.
- Chain panjang atau tidak wajar perlu dipetakan sebagai masukan pemetaan permukaan dan validasi.

## When Not To Use

- History kosong dan authorization belum aktif — tidak ada yang dianalisis; skill ini tidak memancing redirect sendiri.
- Mengikuti redirect ke domain out-of-scope demi "melihat isinya" — dilarang; respons origin out-of-scope tidak boleh menjadi reasoning content (ROADMAP §29).
- Menguji redirect pada endpoint state-changing tanpa approval yang mencakupnya.
- Menilai logika routing framework tanpa bukti trafik — itu wilayah review kode.

## Authorization Preconditions

- Analisis history tidak menuntut status khusus; replay konfirmasi butuh `granted`/`offline-lab` plus approval (ROADMAP §8, §9).
- Redirect no-follow adalah default; keputusan follow selalu didahului scope validation per hop (ROADMAP §29).
- Approval tidak otomatis mencakup hop yang belum diperiksa — tiap tujuan direvalidasi sebelum diikuti.
- Nilai parameter dan header Location adalah data (ROADMAP §24): URL di dalamnya tidak pernah dikunjungi tanpa jalur capability ber-approval.

## Required Context

- Sampel request/response ber-3xx dari history: endpoint sumber, parameter, dan nilai Location per hop.
- Daftar parameter yang berpotensi menjadi tujuan redirect di aplikasi (next, returnTo, url, dan variasinya).
- Scope entries: domain dan path yang sah sebagai tujuan redirect.
- Konteks bisnis: alur yang memang sah me-redirect antar domain (SSO, payment gateway, CDN).

## Required Capabilities


- `inspect_request` — membedah parameter request dan header Location per hop.
- `request_replay` — konfirmasi terkendali perilaku redirect dengan variasi parameter, di dalam approval.

Analisis pasif (dua capability pertama) tidak mengirim traffic; replay hanya berjalan pada provider proxy dengan egress (ROADMAP §4.1, §5.2, §29).

## Core Concepts

- **No-follow default**: redirect tidak diikuti otomatis; tiap hop yang diikuti direvalidasi terhadap scope terlebih dulu (ROADMAP §29).
- **Open redirect = parameter yang dikendalikan server**: hanya relevan bila nilai parameter benar-benar memengaruhi tujuan redirect — buktikan dengan replay terkontrol.
- **Pola validasi**: allowlist domain, validasi relatif, dan regex prefix punya pola bypass lazim masing-masing (encoding, subdomain tiruan, `//evil.com`, backslash).
- **Rantai berlapis**: open redirect sering dipakai sebagai trampolin antar domain untuk menyamarkan tujuan akhir.
- **Redirect client-side**: meta-refresh dan JavaScript redirect tidak tampak di status 3xx — hanya terdeteksi dari konten body yang terekam.

## Reasoning Workflow

1. Tarik seluruh respons 3xx lewat `list_history`; susun rantai per request asal: hop, status, dan Location tiap hop.
2. Tandai hop yang tujuannya keluar dari host asal; klasifikasikan: in-scope, out-of-scope, atau ambigu.
3. Inventarisasi parameter bernilai URL/path pada endpoint yang me-redirect; catat nilai dan tujuan efektifnya.
4. Nilai pola validasi tujuan dari variasi nilai parameter yang terlihat di history: allowlist, relatif saja, atau bebas.
5. Untuk kandidat open redirect, susun hypothesis bypass dan konfirmasi lewat replay terkendali: satu variabel per iterasi, no-follow pada hop lanjutan, tujuan uji di dalam batas approval.
6. Jangan mengikuti redirect ke out-of-scope: catat Location-nya sebagai evidence dan hentikan rantai di situ (ROADMAP §29).
7. Simpan peta rantai dan temuan berkaidah; rutekan konfirmasi dampak (phishing, token leakage) ke skill analisis yang relevan.

## Allowed Operations

- Membaca dan memetakan rantai redirect dari history tanpa batas jumlah, karena nol traffic.
- Membedah parameter dan header Location lewat `inspect_request`.
- Replay konfirmasi satu-hop dengan parameter terkendali dan no-follow pada hop lanjutan, di dalam approval (ROADMAP §9, §29).

## Approval Requirements

- Analisis pasif tanpa approval; replay konfirmasi butuh approval scoped: host, path, parameter yang dimutasi, budget, dan expiry (ROADMAP §9).
- Tujuan replay tidak boleh host out-of-scope walau itu inti bukti — nilai header Location pada hop pertama sudah cukup sebagai evidence.
- Redirect yang menyasar domain luar tidak pernah diikuti tanpa scope validation yang mengizinkan (ROADMAP §29).

## Forbidden Operations

- Mengikuti redirect out-of-scope atau mengambil konten dari origin luar scope (ROADMAP §29).
- Menyimpulkan open redirect hanya dari nama parameter tanpa bukti pengaruhnya terhadap Location.
- Menganggap redirect ke domain resmi sebagai vulnerability tanpa analisis konteks bisnis.
- Menyimpan URL berisi token atau kredensial yang terlihat di Location tanpa redaksi (ROADMAP §23).
- Melanjutkan eksekusi setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Peta rantai redirect per request asal: hop, status code, Location, dan referensi request id.
- Tabel parameter redirect: endpoint, nama parameter, nilai teramati, dan tujuan efektifnya.
- Bukti replay konfirmasi (bila ada): request yang dikirim, Location hasil, dan referensi approval.
- Daftar rantai yang dihentikan di batas scope beserta alasannya.

## False Positive Checks

- Redirect ke domain resmi (SSO, CDN, payment provider) yang sah — cek konteks bisnis sebelum melaporkan.
- Meta-refresh dan JavaScript redirect bersifat client-side dan tidak tampak di 3xx; jangan klaim "tidak ada redirect" hanya dari status code.
- Parameter URL yang hanya dipakai klien (tidak diproses server) bukan open redirect — verifikasi pengaruhnya ke Location.
- Validasi yang tampak longgar bisa dilengkapi lapisan lain (middleware, gateway) yang tidak terlihat dari satu sampel.
- Cache atau redirect loop bisa membuat Location basi — pastikan sampel merepresentasikan perilaku kini.

## Severity Guidance

- Open redirect terkonfirmasi pada domain utama yang dipakai user: sedang; naik bila berantai dengan token di URL atau dipakai pada callback OAuth.
- Redirect yang menyamarkan domain asli dalam skenario phishing dinilai ulang oleh skill penerima dengan konteks penyalahgunaan.
- Redirect terbatas ke path relatif dengan validasi lemah: rendah atau informatif.
- Status lifecycle tetap `suspected` sampai tervalidasi (ROADMAP §26); skill ini memasok bukti Location dan rantainya.

## Stop Conditions

- Chain menunjuk origin out-of-scope → stop di hop itu, catat Location, jangan lanjut (ROADMAP §29).
- Replay menghasilkan side effect tak terduga (email, notifikasi, perubahan state) → berhenti dan laporkan (ROADMAP §10).
- Stop condition umum §10 terpicu: budget habis, approval dicabut, authorization expired.

## Output Format

- Peta rantai redirect per endpoint sumber dengan referensi bukti per hop.
- Daftar kandidat open redirect berkaidah: parameter, pola validasi, hypothesis bypass, dan status lifecycle.
- Rekomendasi routing: skill penerima untuk konfirmasi dampak dan pelaporan.

## Related Skills

- `http-traffic-analysis` — sumber history dan baseline di hulu.
- `http-request-replay` — disiplin replay yang sama untuk konfirmasi aktif.
- `oauth-security` — validasi redirect_uri pada alur OAuth saling melengkapi.
- `web-authentication` — redirect pasca-login dan alur SSO.
- `security-misconfiguration` — penerima temuan konfigurasi redirect yang lemah.
- `ssrf-analysis` — pembeda vektor: redirect diikuti klien versus fetch server-side.
