---
name: xss-analysis
description: >
  Use when responses reflect user input or client-side scripts consume
  attacker-influenced data: locate reflections with unique inert canary
  markers, classify the output context (HTML body, attribute, JavaScript,
  URL), analyze DOM sources and sinks statically from captured files, and
  separate mere reflection from a credible execution and impact story.
version: 0.1.0
risk: medium
---

# XSS Analysis

## Purpose

- Menganalisis indikasi XSS pada tiga varian: reflected, stored, dan DOM — dengan canary marker unik yang inert, bukan payload aktif.
- Mengklasifikasikan konteks output setiap refleksi (HTML body, attribute, JavaScript string, URL) karena keberbahayaan refleksi ditentukan konteks, bukan keberadaan string.
- Menegaskan batas: indikasi refleksi bukan vulnerability tervalidasi — butuh konteks eksekusi dan dampak yang bisa diargumentasikan.

## When To Use

- Parameter atau field yang terefleksi di respons: hasil pencarian, pesan error, nama profil, komentar.
- Skrip klien mengonsumsi data yang dipengaruhi penyerang (parameter URL, hash, postMessage, referrer) dan perlu analisis source/sink.
- Input tersimpan dan dirender ulang pada halaman lain — kandidat stored XSS.

## When Not To Use

- Authorization `pending` atau scope tidak mencakup endpoint yang diuji (ROADMAP §8).
- Mencari eksekusi nyata dengan payload script (alert/prompt, event handler, javascript URI) — skill ini bekerja dengan marker inert saja.
- Halaman sepenuhnya statis tanpa refleksi dan tanpa konsumsi data klien — tidak ada permukaan XSS.
- Demo eksekusi aktif di browser untuk program tertentu — jalur eskalasi terpisah dengan kesepakatan owner tersendiri.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; approval conditional untuk replay marker (ROADMAP §8, §9).
- Canary stored hanya pada akun uji sendiri; jangan pernah menyimpan marker yang akan dirender ke user nyata tanpa rencana pembersihan.
- Analisis DOM statis dari file JavaScript terekam boleh berjalan tanpa approval — tidak ada traffic ke target.
- Alur authenticated memakai credential reference (ROADMAP §23).

## Required Context

- Daftar parameter dan field yang berpotensi terefleksi dari web-surface-mapping dan history.
- Baseline response tanpa marker untuk tiap endpoint yang diuji.
- File JavaScript terekam dari target (hasil capture proxy) sebagai bahan analisis statis DOM.
- Header keamanan respons: CSP, X-Content-Type-Options, dan konfigurasi framework escaping yang tampak.
- Pemahaman siapa yang melihat render: halaman publik, halaman akun sendiri, atau halaman user lain.

## Required Capabilities

- `inspect_request` — memeriksa request terekam: parameter, header, dan format input yang mungkin terefleksi.
- `list_history` — menemukan respons yang mengandung refleksi dan baseline per endpoint.
- `request_replay` — mengirim request dengan canary marker unik, satu marker per iterasi.
- `response_comparison` — menemukan posisi marker di respons dan membandingkan konteks antar iterasi.
- Skill tidak menentukan provider; replay hanya berjalan di provider proxy (ROADMAP §4.1, §5.2).

## Core Concepts

- **Canary marker, bukan payload**: string unik per iterasi yang aman dirender di konteks mana pun dan tidak mengandung karakter sintaksis HTML/JavaScript — marker mengukur refleksi, bukan eksekusi.
- **Konteks output menentukan risiko**: teks HTML body, attribute quoted atau unquoted, dalam tag script, dalam URL atau href, dalam komentar — escaping yang benar di satu konteks belum tentu melindungi konteks lain.
- **Refleksi bukan vulnerability**: marker yang muncul mentah baru bermakna bila konteksnya dapat dieksekusi (attribute tanpa escape, string script, sink DOM) dan dampaknya melintasi batas user.
- **DOM XSS via analisis statis**: telusuri source (location hash/search, referrer, postMessage, window name) menuju sink (innerHTML, outerHTML, document.write, eval, timer berbasis string) dari file JavaScript terekam; tandai jalur tanpa sanitasi.
- **Encoding berlapis**: nilai bisa terenkode berulang sehingga refleksi mentah di respons belum tentu mentah di browser — periksa bagaimana browser menafsirkannya.
- **Mitigasi dicatat, bukan dianggap absen**: CSP, auto-escape templating, dan sanitizer adalah mitigasi nyata yang menurunkan dampak — dilaporkan apa adanya (ROADMAP §26).

## Reasoning Workflow

1. Pilih endpoint dengan potensi refleksi; rekam baseline tanpa marker.
2. Replay dengan canary marker unik; temukan posisi tiap kemunculan lewat response comparison.
3. Klasifikasikan konteks output tiap kemunculan dan nilai escaping yang terlihat di konteks itu.
4. Untuk stored: simpan marker via alur akun uji, temukan halaman render-nya, periksa siapa yang melihat render (boundary antar user), lalu bersihkan.
5. Untuk DOM: analisis statis file JavaScript — daftar source, sink, dan jalur yang tersambung tanpa sanitasi; catat sink yang terjangkau dari URL.
6. Susun narasi eksekusi: source → konteks → sink → aksi penyerang → dampak; tandai gap bila narasi tidak tertutup.
7. Jalankan FP check; perbarui status hypothesis (ROADMAP §26).

## Allowed Operations

- Replay GET atau parameter dengan canary marker inert, satu marker per iterasi, dalam budget approval.
- Penyimpanan marker via alur akun uji sendiri untuk kandidat stored, dengan pembersihan setelah pengujian.
- Analisis statis file JavaScript dan respons dari data terekam.
- Perbandingan respons antar iterasi dan dokumentasi konteks output.

## Approval Requirements

- Replay marker ber-risk MEDIUM → approval conditional scoped per endpoint (ROADMAP §8, §9).
- Penyimpanan marker pada endpoint stateful → HIGH, approval eksplisit; pilih fungsi yang mudah dibersihkan (ROADMAP §8).
- Demo eksekusi aktif di browser berada di luar skill ini dan butuh kesepakatan owner tersendiri bila benar-benar diperlukan.
- Approval kadaluarsa atau dicabut → berhenti; renewal sebagai approval baru (ROADMAP §9).

## Forbidden Operations

- Payload eksekusi nyata: tag script aktif, event handler inline, javascript URI, atau payload alert/prompt — hanya marker inert.
- Menyimpan payload yang dirender ke user lain dan membiarkannya tersisa — marker stored wajib dibersihkan.
- Membuktikan dampak lintas user dengan menyerang user nyata — boundary antar user dinilai dari konteks render, bukan dari korban sungguhan.
- Chain eksploitasi (XSS menuju aksi stateful) tanpa approval tersendiri.
- Melanjutkan eksekusi setelah stop condition terpicu (ROADMAP §10).

## Evidence Requirements

- Minimum set ROADMAP §25: baseline evidence, reproduction steps, expected behavior, actual behavior, impact, false-positive analysis, scope reference, confidence, sanitized artifact.
- Posisi refleksi: kutipan respons di sekitar marker (ringkas), klasifikasi konteks, dan penilaian escaping.
- Untuk DOM: daftar source, sink, jalur, beserta file dan lokasinya sebagai referensi.
- Untuk stored: bukti siapa-melihat-apa pada render dan bukti pembersihan marker setelah uji.
- Hash dan provenance tiap evidence (ROADMAP §25).

## False Positive Checks

- Output ter-escape dengan benar di konteksnya (HTML entity, attribute encoding) — refleksi terlihat tetapi tidak dapat dieksekusi.
- Refleksi di konteks aman: dalam komentar HTML, attribute yang selalu quoted dan terenkode, elemen non-eksekusi (template/noscript), atau respons non-HTML (JSON API) tanpa render.
- Encoding berlapis: nilai yang terenkode ganda tidak akan terurai menjadi sintaksis aktif di browser.
- CSP ketat (nonce/hash, tanpa unsafe-inline) memitigasi eksekusi — catat sebagai mitigasi, bukan sebagai ketiadaan kerentanan.
- Refleksi berasal dari cache, atau dari data user sendiri yang hanya dirender balik ke dirinya — self-XSS, bukan lintas user.

## Severity Guidance

- Stored, lintas user, pada halaman sensitif, tanpa mitigasi CSP → tinggi.
- Reflected pada URL yang mudah tersebar (tautan, email) → sedang, tergantung distribusi dan mitigasi.
- DOM XSS dari source yang dikontrol penyerang menuju sink tanpa sanitasi → sedang hingga tinggi sesuai jangkauan source.
- Self-XSS murni → rendah; naik hanya bila bisa dirantai dengan mekanisme lain.
- Refleksi tanpa konteks eksekusi → bukan temuan; catat sebagai hypothesis dengan dampak yang belum ada.

## Stop Conditions

- Marker stored ternyata dirender ke user nyata di luar akun uji → berhenti, bersihkan, laporkan (ROADMAP §10).
- Respons memuat data sensitif → redact dan laporkan (ROADMAP §10).
- 429, repeated 5xx, budget habis, approval dicabut, atau authorization expired → stop (ROADMAP §10).

## Output Format

- Peta refleksi: endpoint, parameter, posisi dan konteks output, penilaian escaping, status.
- Daftar kandidat DOM: pasangan source-sink, file referensi, jalur sanitasi yang ada atau tidak ada.
- Narasi eksekusi dan dampak per kandidat, status lifecycle, dan sisa FP risk.

## Related Skills

- `web-surface-mapping` — inventaris parameter dan field yang berpotensi terefleksi.
- `http-proxy-traffic-analysis` — sumber file JavaScript terekam untuk analisis statis DOM.
- `payload-selection` — payload bermetadata bila suatu saat eskalasi terkurasi diizinkan (ROADMAP §22).
- `security-misconfiguration` — konfigurasi header keamanan seperti CSP.
- `waf-analysis` — konteks proteksi yang memengaruhi interpretasi respons.
- `false-positive-analysis` — penyisiran FP sebelum status naik.
- `vulnerability-validation` — kerangka lifecycle finding (ROADMAP §26).
