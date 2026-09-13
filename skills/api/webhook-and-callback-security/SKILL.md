---
name: webhook-and-callback-security
description: >
  Use when an application fetches caller-controlled URLs or delivers
  callbacks: signature verification, replay protection, and redirect or DNS
  handling of server-side fetches — with the same strictness as SSRF
  analysis, tester-owned canary listeners only.
version: 0.1.0
risk: medium
---

# Webhook and Callback Security

## Purpose

- Menilai keamanan server-side fetch yang URL-nya dipengaruhi aplikasi atau pengguna: pendaftaran webhook, pengiriman callback, dan import via URL.
- Menguji kontrol yang melindungi fetch tersebut: verifikasi signature (HMAC), proteksi replay, penanganan redirect, dan validasi DNS/IP.
- Menegaskan aturan ketat setara `ssrf-analysis`: hanya canary milik tester, dilarang menyentuh endpoint metadata atau host internal, dan fetch yang terbukti menjangkau internal adalah stop plus laporan segera (ROADMAP §10).

## When To Use

- Fitur target menerima URL dari pengguna (registrasi webhook, fetch avatar/import by URL) atau mengirim callback keluar.
- History menunjukkan request server-to-server dengan header signature yang bisa diverifikasi ulang secara lokal.
- `ssrf-analysis` sudah mengidentifikasi permukaan fetch dan proteksi callback perlu didalami.

## When Not To Use

- Tidak ada mekanisme server-side fetch atau callback pada target.
- Tidak ada canary/listener milik tester atau persetujuan eksplisit atas out-of-band interaction — pengujian tidak bisa berjalan dengan aman.
- Niatnya menyentuh endpoint metadata cloud atau jaringan internal — dilarang mutlak, di luar diskusi.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; approval menyebut eksplisit canary host dan batas jumlah pengiriman (ROADMAP §8, §9).
- Canary hanya host milik tester yang tercantum di approval; tujuan fetch lain di luar target adalah pelanggaran.
- Indikasi fetch mencapai host internal atau metadata = stop condition, bukan eksplorasi lanjutan (ROADMAP §10).

## Required Context

- Endpoint yang menerima URL atau mengirim callback, dari inventaris dan history.
- Skema signature yang teramati: header tanda tangan, cakupan payload yang ditandatangani, keberadaan timestamp atau nonce.
- Program terms soal out-of-band interaction — sebagian program melarang atau membatasinya.
- Canary milik tester yang siap menerima interaksi dan mencatat waktu, sumber, dan header.

## Required Capabilities

- `request_replay` — mengirim variasi payload callback dan signature di dalam approval.
- `list_history` — membaca pola callback terekam: header signature, urutan pengiriman, dan pengulangan.
- Verifikasi HMAC dan analisis payload dilakukan secara lokal atas data terekam; capability tambahan tidak diperlukan.

Skill tidak menentukan provider; replay hanya dijalankan provider proxy yang punya privilege egress (ROADMAP §4.1, §5.2, §11).

## Core Concepts

- **Verifikasi signature**: HMAC atas payload dengan kunci bersama — diuji dengan memodifikasi payload dan mengamati apakah tanda tangan lama masih diterima.
- **Proteksi replay**: timestamp dan nonce membatasi umur permintaan; payload bertanda tangan sama yang diterima lagi adalah observation.
- **Redirect pada fetch**: callback fetch yang mengikuti redirect membuka pembelokan tujuan; perilaku yang diharapkan adalah penolakan atau re-validasi tujuan.
- **Validasi DNS/IP**: resolusi yang divalidasi saat fetch, bukan hanya saat input — TOCTOU DNS dianalisis dari perilaku, tidak dieksploitasi ke host nyata.
- **Canary milik tester**: satu-satunya tujuan out-of-band yang sah; detail interaksi (waktu, sumber, header) menjadi evidence.
- **Batas eksfiltrasi**: canary menangkap bukti interaksi saja — menyisipkan data target ke payload canary dilarang.

## Reasoning Workflow

1. Petakan permukaan fetch dari history dan inventaris: input URL, pengiriman webhook, dan parameter terkait.
2. Amati skema signature dari history; catat header, cakupan field yang ditandatangani, dan keberadaan timestamp/nonce.
3. Susun rencana uji minimal: payload signature dimodifikasi, payload dikirim ulang (replay), dan callback diarahkan ke canary milik tester.
4. Ajukan approval yang menyebut canary host, jumlah pengiriman, dan larangan tujuan internal/metadata.
5. Jalankan variasi satu per satu; untuk signature, bandingkan respons payload valid versus dimodifikasi — respons setara berarti signature tidak diverifikasi.
6. Untuk redirect, canary merespons satu lapis redirect ke canary kedua milik tester; amati apakah fetch mengikuti dan tercatat di canary.
7. Fetch yang terindikasi menjangkau host internal atau metadata (dari error, timing, atau perilaku) = STOP; simpan evidence, laporkan segera (ROADMAP §10).
8. Tutup dengan penilaian per kontrol: verifikasi signature, proteksi replay, disiplin redirect, dan validasi tujuan.

## Allowed Operations

- Replay payload callback/signature ke endpoint in-scope dengan budget kecil per endpoint.
- Interaksi out-of-band hanya ke canary milik tester yang tercantum di approval.
- Verifikasi ulang HMAC secara lokal terhadap payload yang terekam.

## Approval Requirements

- Approval menyebut endpoint, jumlah pengiriman, canary host, dan larangan eksplisit tujuan internal/metadata (ROADMAP §9).
- Pengiriman ulang (replay) dinyatakan eksplisit karena memicu aksi kedua di sisi penerima.
- Perubahan tujuan callback di luar canary yang disetujui butuh approval baru — bukan improvisasi saat runtime.

## Forbidden Operations

- Fetch ke endpoint metadata cloud (169.254.x.x dan serupa) atau host internal — dilarang mutlak; indikasi keberhasilan = stop plus lapor (ROADMAP §10).
- Mengarahkan callback target ke host pihak ketiga yang bukan milik tester.
- Menyisipkan data target ke payload canary — canary menangkap interaksi, bukan data.
- Melewati signature untuk memaksa eksekusi aksi stateful di sisi penerima.

## Evidence Requirements

- Pasangan payload valid-versus-dimodifikasi beserta responsnya (referensi replay id).
- Catatan interaksi canary: waktu, sumber, header — tanpa data target di dalamnya.
- Analisis replay: payload yang diterima ulang beserta jeda waktunya.
- Seluruh artifact tersanitasi dan ter-hash (ROADMAP §25).

## False Positive Checks

- Signature diverifikasi di gateway, bukan aplikasi — lokasi kontrol memengaruhi makna temuan.
- Jendela timestamp yang longgar bisa berupa keputusan desain; ukur nilainya sebelum mengklaim kelalaian.
- Kegagalan fetch yang tampak seperti blokir internal bisa berarti egress target memang tertutup — kontrol bekerja, bukan temuan.
- Retry otomatis dari infrastruktur webhook bukan kelemahan proteksi replay.

## Severity Guidance

- Callback dapat dibelokkan ke host internal atau metadata: tinggi hingga kritikal (dilaporkan segera saat stop).
- Signature tidak diverifikasi pada aksi stateful: tinggi.
- Payload replay diterima tanpa proteksi: sedang hingga tinggi sesuai dampak aksi penerima.
- Redirect diikuti ke host eksternal yang aman (non-internal): sedang.

## Stop Conditions

- Indikasi fetch mencapai host internal atau metadata → hentikan semua pengujian, simpan evidence, laporkan segera (ROADMAP §10).
- Canary menerima interaksi dari sumber tak terduga → berhenti dan evaluasi sebelum lanjut.
- Aksi stateful terpicu tanpa niat di sisi penerima → berhenti, laporkan (ROADMAP §10).
- Stop condition umum §10: budget habis, authorization expired, approval dicabut.

## Output Format

- Peta permukaan fetch/callback dengan skema signature yang teramati.
- Hasil uji per kontrol: signature, replay, redirect, validasi tujuan — tiap baris observation dengan bukti.
- Laporan stop (bila terjadi) beserta evidence minimum dan rute eskalasi.

## Related Skills

- `ssrf-analysis` — saudara terdekat dengan aturan ketat yang sama.
- `http-proxy-request-mutation` — mekanisme variasi payload lewat capability.
- `rest-api-testing` — konteks endpoint input yang menerima URL.
- `vulnerability-validation`, `false-positive-analysis` — kontrak validasi dan triase.
