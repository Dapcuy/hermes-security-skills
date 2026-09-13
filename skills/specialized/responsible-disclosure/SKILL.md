---
name: responsible-disclosure
description: >
  Use when a validated finding needs coordinated disclosure: drafting the
  vendor report and timeline, respecting embargoes, and ensuring nothing
  is published without explicit human approval.
version: 0.1.0
risk: low
---

# Responsible Disclosure

## Purpose

- Menjalankan proses coordinated disclosure untuk temuan yang sudah tervalidasi: kontak vendor, embargo, dan timeline yang disepakati.
- Memastikan tidak ada publikasi otomatis: setiap komunikasi keluar dan setiap publikasi membutuhkan keputusan human (ROADMAP §2, §28).
- Menghasilkan draft report dan timeline disclosure yang bisa ditinjau, direvisi, dan disetujui user sebelum dikirim.
- Menjaga status klasifikasi temuan (ROADMAP §28) tetap akurat sepanjang proses: vendor-notified, confirmed-by-vendor, publicly-disclosed.

## When To Use

- Temuan mencapai status `confirmed` (ROADMAP §26) dan user memutuskan untuk melapor ke vendor/program.
- Program bug bounty memiliki kebijakan disclosure yang wajib diikuti.
- Vendor meminta koordinasi waktu publikasi (embargo) dan perlu pelacakan timeline.
- Beberapa pihak terlibat (vendor, program, CERT) dan urutan komunikasinya perlu dikelola.

## When Not To Use

- Temuan masih `suspected`/`needs-validation` — selesaikan validasi dulu (ROADMAP §26).
- Sebagai jalur mempublikasikan sendiri tanpa persetujuan program/vendor — auto-publish adalah non-goal (ROADMAP §2).
- Menyusun detail eksploitasi baru demi "melengkapi" report — report memakai evidence yang sudah ada (ROADMAP §25).
- Kontak ke pihak ketiga yang tidak tercantum dalam kebijakan program tanpa arahan user.

## Authorization Preconditions

- Disclosure dilakukan atas temuan dari engagement yang authorization-nya sah dan tercatat (ROADMAP §8).
- Kebijakan disclosure program (security.txt, terms program, kontrak) menjadi batas utama: kanal, format, dan larangannya.
- Semua komunikasi eksternal dikirim oleh human atau atas persetujuan eksplisitnya — skill hanya menyiapkan draft (ROADMAP §2, §9).
- Klasifikasi status ROADMAP §28 dicatat sejak awal dan di-update di tiap tonggak.

## Required Context

- Report temuan final dari security-reporting: reproduction, impact, remediation, evidence ter-sanitasi (ROADMAP §25).
- Kebijakan disclosure yang berlaku: kanal kontak, SLA program, aturan embargo, batasan publikasi.
- Klasifikasi novelty temuan (ROADMAP §28) — khususnya bila potentially-unknown.
- Identitas pihak: vendor, program, peneliti, dan siapa yang berhak tahu apa.
- Preferensi user: kerahasiaan, tenggat, dan seberapa detail PoC yang boleh dibagikan.

## Required Capabilities

Tidak ada capability aktif yang diperlukan. Skill bekerja pada report, kebijakan, dan catatan komunikasi yang sudah ada; pengiriman komunikasi dilakukan human atau alat komunikasi user, bukan dari skill ini (ROADMAP §4.1, §8).

## Core Concepts

- **Coordinated disclosure**: vendor diberi kesempatan memperbaiki sebelum detail publik; jadwal disepakati bersama, bukan lewat ultimatum.
- **Embargo**: periode kerahasiaan bersama; pihak yang menerima detail terikat tidak mempublikasikan sebelum tanggal yang disepakati.
- **Human approval gate**: setiap kiriman keluar (draft, email, publikasi) menunggu persetujuan eksplisit; tidak ada jalur otomatis (ROADMAP §2).
- **Redaksi**: report dibersihkan dari kredensial, data user nyata, dan informasi yang tidak perlu sebelum keluar dari engagement (ROADMAP §23, §25).
- **Klasifikasi status §28**: dari `under-review` menjadi `vendor-notified`, `confirmed-by-vendor`, hingga `publicly-disclosed` — dipetakan sepanjang timeline.
- **Tanpa klaim zero-day**: istilah zero-day tidak pernah dipakai otomatis; klasifikasi mengikuti ROADMAP §28 dan human yang memutuskan.

## Reasoning Workflow

1. Verifikasi status temuan `confirmed` dan kelengkapannya terhadap evidence minimum (ROADMAP §25, §26).
2. Kumpulkan kebijakan disclosure yang berlaku dan petakan kanal kontak resminya.
3. Susun draft report yang terredaksi: tanpa kredensial, tanpa data user nyata, PoC sebatas yang diizinkan kebijakan.
4. Susun timeline usulan: tanggal kontak, target acknowledgment, jendela perbaikan, tanggal publikasi yang diusulkan.
5. Sajikan draft + timeline ke user untuk persetujuan; revisi sesuai masukan.
6. Setelah user mengirim kontak, catat tanggal dan status; update klasifikasi §28 menjadi `vendor-notified`.
7. Lacak berjalan: acknowledgment vendor, komitmen fix, permintaan perpanjangan embargo — tiap perubahan dicatat; publikasi kembali menunggu persetujuan human.

## Allowed Operations

- Menyusun dan merevisi draft report disclosure dan draft komunikasi vendor.
- Menyusun dan memelihara timeline disclosure beserta catatan statusnya.
- Mencatat komunikasi yang dilaporkan user (tanggal, kanal, ringkasan) ke case memory.
- Merekomendasikan eskalasi (mis. jalur CERT) bila kanal resmi tidak merespons — sebagai rekomendasi untuk human.

## Approval Requirements

- Setiap draft yang meninggalkan engagement (dikirim ke vendor/program/pihak ketiga) wajib disetujui human terlebih dahulu (ROADMAP §2, §9).
- Publikasi apa pun (posting, permintaan CVE, write-up) adalah keputusan human — skill berhenti di draft.
- Perubahan tenggat/embargo yang dinegosiasikan vendor dicatat dan dikonfirmasi ke user sebelum disepakati.
- Approval bersifat per-aksi: persetujuan mengirim report bukan persetujuan mempublikasikan.

## Forbidden Operations

- Auto-publish dalam bentuk apa pun: posting, pengiriman massal, permintaan CVE tanpa persetujuan human (ROADMAP §2).
- Menyatakan temuan sebagai zero-day atau mengklaim novelty yang belum diverifikasi (ROADMAP §28).
- Menyertakan nilai kredensial, data user nyata, atau data lintas scope dalam report (ROADMAP §23, §25).
- Mengirim report ke pihak di luar kebijakan program tanpa arahan eksplisit user.
- Menggunakan bahasa ancaman, tenggat ultimatum, atau tuntutan hadiah dalam komunikasi.

## Evidence Requirements

- Draft report dengan versi (v1, v2) dan catatan revisi, semuanya terredaksi.
- Timeline: tanggal kontak, acknowledgment, komitmen, dan publikasi — beserta status klasifikasi §28 pada tiap titik.
- Catatan persetujuan human per aksi keluar (apa yang disetujui, kapan).
- Salinan komunikasi yang dilaporkan user disimpan sebagai case memory — bukan knowledge canonical (ROADMAP §24, §27).

## False Positive Checks

- Pastikan temuan tidak duplikat dari laporan yang sudah ada (known issues program) sebelum proses disclosure berjalan.
- Cek ulang severity: klaim berlebih di report merusak kredibilitas dan bisa melanggar batas program.
- Pastikan evidence yang dilampirkan sudah lolos sanitasi (tanpa kredensial/PII) — periksa ulang sebelum tiap versi dikirim.
- Verifikasi kanal kontak resmi (domain program/security.txt), bukan alamat yang tidak bisa diverifikasi.

## Severity Guidance

- Severity dalam report mengikuti hasil validasi (ROADMAP §26) — bukan dinaikkan demi dampak disclosure.
- Bila vendor menilai lebih rendah, catat kedua penilaian beserta dasarnya; keputusan respons ada di human.
- Temuan potentially-unknown (ROADMAP §28) mengikuti alur khusus: stop, redaksi, inform user, human memutuskan — disclosure tidak berjalan otomatis.

## Stop Conditions

- Vendor tidak bisa dihubungi lewat kanal resmi manapun → berhenti pada rekomendasi (jalur CERT/CVE) dan serahkan keputusan ke human.
- Vendor atau program mengancam hukum / melanggar kesepakatan → hentikan komunikasi lanjutan, inform user.
- Draft ditemukan memuat data yang belum terredaksi → tarik draft, sanitasi ulang sebelum lanjut.
- User meminta publikasi tanpa persetujuan program padahal kebijakan mewajibkan koordinasi → tegaskan batas kebijakan, minta keputusan eksplisit human.

## Output Format

- Draft disclosure report (versi + tanggal) yang siap ditinjau, dengan catatan redaksi.
- Timeline disclosure: tabel tanggal per tonggak (kontak, acknowledgment, fix, publikasi) dan status §28 saat ini.
- Daftar keputusan yang menunggu human beserta opsi dan konsekuensinya.

## Related Skills

- `security-reporting` — sumber draft report teknis yang menjadi dasar disclosure.
- `novelty-assessment` — klasifikasi ROADMAP §28 sebelum komunikasi keluar.
- `evidence-handling` — sanitasi dan integritas evidence yang dilampirkan (ROADMAP §25).
- `engagement-scoping` — kebijakan program dan batas scope yang membatasi disclosure.
- `vulnerability-validation` — memastikan hanya temuan `confirmed` yang masuk proses disclosure.
