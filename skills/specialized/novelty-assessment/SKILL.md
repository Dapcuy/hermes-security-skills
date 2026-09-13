---
name: novelty-assessment
description: >
  Use when a finding's novelty must be classified before reporting:
  determine whether the vulnerability class is publicly known, whether the
  instance is target-specific, and whether there is a meaningful variation,
  then recommend a disclosure path - never auto-declaring a zero-day.
version: 0.1.0
risk: low
---

# Novelty Assessment

## Purpose

- Menilai kebaruan (novelty) sebuah temuan sebelum dilaporkan, sesuai klasifikasi ROADMAP §28: dari `known-common-pattern` hingga `publicly-disclosed`.
- Memisahkan tiga pertanyaan yang sering tercampur: apakah CLASS kerentanannya sudah dikenal, apakah INSTANCE-nya spesifik pada target ini, dan apakah ada VARIASI yang berarti.
- Menghasilkan classification + rationale + rekomendasi disclosure path yang bisa diaudit — bukan opini sekilas.
- Menegakkan batas §28: skill ini TIDAK PERNAH menyatakan `zero-day` secara otomatis; klaim kebaruan tinggi selalu berakhir pada jalur human decision.

## When To Use

- Temuan sudah `confirmed` (ROADMAP §26) dan perlu diposisikan sebelum dilaporkan ke program/vendor.
- Temuan terasa "sudah pernah ada" dan perlu dipilah: pola umum, instansi spesifik target, atau varian baru.
- Rantai temuan (`vulnerability-chaining`) menghasilkan kombinasi yang kebarunannya perlu dinilai sebagai satu kesatuan.
- Sebelum `responsible-disclosure` berjalan — jalur disclosure bergantung pada klasifikasi kebaruan.

## When Not To Use

- Untuk membenarkan temuan — validasi teknis tetap tugas `vulnerability-validation` dan `false-positive-analysis`; novelty menilai kebaruan, bukan kebenaran.
- Saat temuan masih `suspected`/`needs-validation` — klasifikasi atas temuan belum terbukti hanya menghasilkan noise.
- Sebagai pengganti riset literatur manusia — skill ini memetakan temuan terhadap sumber yang ada, bukan menggantikan penelusuran mendalam maintainer.
- Untuk memutuskan publikasi — tidak ada auto-publish di project ini (ROADMAP §2, §28).

## Authorization Preconditions

- Penilaian berjalan atas temuan dalam satu engagement yang sah (authorization `granted`/`offline-lab` pada case terkait).
- Membaca evidence kasus lewat capability read-only tidak mengirim traffic ke target (ROADMAP §5.1).
- Pencarian referensi eksternal dilakukan manual oleh human terhadap sumber yang terdokumentasi — skill ini tidak melakukan fetch jaringan; bila verifikasi lab diperlukan, jalankan lewat alur validasi ber-approval.

## Required Context

- Finding yang sudah tervalidasi beserta evidence minimum-nya (ROADMAP §25): reproduction, expected/actual behavior, impact.
- Knowledge base lokal: entry berstate `reviewed`/`trusted` di `knowledge/` (ROADMAP §27) sebagai pembanding pola yang sudah dikenal.
- Evidence kasus dari engagement sebelumnya yang relevan (case memory), dirujuk sebagai reference — bukan disalin mentah ke konteks.
- Referensi eksternal yang terdokumentasi: advisori vendor, CVE, tulisan riset, writeup program — dengan sumber dan tanggal yang dicatat.
- Konteks program: kebijakan disclosure program/vendor tujuan (ROADMAP §28).

## Required Capabilities

- `list_history` — opsional, read-only: membaca evidence dan riwayat kasus terkait dari event store saat penilaian membutuhkan konteks engagement (ROADMAP §5.1, §11). Tanpa capability ini, penilaian tetap bisa berjalan atas finding dan knowledge base yang diserahkan.

## Core Concepts

- **Klasifikasi §28**: `known-common-pattern`, `target-specific-instance`, `novel-variant`, `potentially-unknown`, `under-review`, `vendor-notified`, `confirmed-by-vendor`, `publicly-disclosed`.
- **Tiga kriteria kebaruan**:
  - Class: apakah class kerentanan sudah dikenal dan terdokumentasi (CWE, OWASP, advisori, knowledge base)?
  - Instance: apakah instansinya spesifik target (endpoint, parameter, konfigurasi khusus target ini)?
  - Variasi: apakah ada variasi yang berarti — teknik trigger, rantai kondisi, atau kombinasi yang mengubah dampak/deteksi — atau sekadar instansi biasa dari pola umum?
- **Bukti vs klaim**: classification wajib disertai rationale yang merujuk sumber; ketiadaan bukti kebaruan BUKAN bukti kebaruan (absence of evidence fallacy).
- **Batas zero-day**: label `potentially-unknown` adalah classification tertinggi yang boleh diusulkan; kata "zero-day" tidak pernah keluar dari skill ini (ROADMAP §28).
- **Jalur eskalasi §28**: bila potentially novel high-impact — stop active testing, simpan evidence minimum, redact, mark `potentially-unknown`, inform user; human yang memutuskan.

## Reasoning Workflow

1. Pastikan finding sudah tervalidasi (`confirmed`/`reproduced`, ROADMAP §26); bila belum, stop dan kembalikan ke jalur validasi.
2. Karakterisasi temuan: class kerentanan, teknik trigger, prasyarat, dan dampak — satu paragraf netral tanpa jargon menjual.
3. Nilai kriteria Class: petakan ke knowledge base lokal (entry `reviewed`/`trusted`, ROADMAP §27) dan referensi eksternal terdokumentasi; catat kecocokan terbaik beserta sumbernya.
4. Nilai kriteria Instance: tentukan apakah yang ditemukan hanya instansi spesifik dari class yang dikenal (endpoint/parameter target ini) atau ada lebih dari itu.
5. Nilai kriteria Variasi: bandingkan teknik trigger dan dampak dengan referensi terdekat; putuskan apakah perbedaannya berarti (mengubah deteksi, dampak, atau prasyarat) atau kosmetik.
6. Bila perlu konteks engagement, baca evidence kasus lewat `list_history` (read-only) dan rujuk sebagai reference.
7. Tentukan classification §28 yang paling didukung bukti; bila tidak yakin, pilih yang lebih konservatif dan naikkan ke `potentially-unknown` hanya dengan rationale eksplisit.
8. Susun rationale: kriteria, sumber pembanding, dan apa yang TIDAK bisa dipastikan secara statis.
9. Rekomendasikan disclosure path sesuai classification (lihat Output Format) dan eskalasi §28 untuk kandidat high-impact — keputusan akhir tetap human.

## Allowed Operations

- Membaca finding, evidence kasus, dan knowledge base lokal (termasuk `list_history` read-only bila tersedia).
- Memetakan temuan terhadap entry knowledge dan referensi eksternal yang terdokumentasi.
- Menghasilkan classification, rationale, dan rekomendasi jalur disclosure.

## Approval Requirements

- Tidak ada approval untuk penilaian read-only atas data engagement yang sudah ada (ROADMAP §8).
- Setiap langkah lanjutan setelah klasifikasi `potentially-unknown` pada temuan high-impact adalah keputusan human — skill ini berhenti pada rekomendasi (ROADMAP §28).
- Kontak ke vendor/program hanya lewat `responsible-disclosure` dengan persetujuan human per kiriman.

## Forbidden Operations

- Menyatakan `zero-day` atau mengekspose PoC ke publik dalam bentuk apa pun (ROADMAP §2, §28).
- Auto-publish, auto-submit, atau mengirim laporan ke channel eksternal tanpa approval human per kiriman.
- Menganggap "tidak ditemukan di knowledge base" sebagai bukti kebaruan.
- Melanjutkan active testing untuk "memperkuat klaim kebaruan" setelah eskalasi §28 dipicu.
- Menyalin data target mentah ke dalam knowledge base — konten target hanya hidup di case memory dengan trust level-nya (ROADMAP §24, §27).

## Evidence Requirements

- Classification akhir + rationale yang merujuk kriteria (class/instance/variation) dan sumber pembandingnya.
- Daftar referensi: entry knowledge (id + state), evidence kasus (reference, bukan salinan), referensi eksternal (judul, penerbit, tanggal) — semua terdokumentasi, ROADMAP §27.
- Pernyataan eksplisit batas penilaian: sumber yang tidak bisa diperiksa dan dampaknya terhadap keyakinan.
- Bila `potentially-unknown`: catatan bahwa alur §28 sudah diinformasikan ke user dan active testing dihentikan.

## False Positive Checks

- Class dikenal ≠ temuan tidak berharga — `target-specific-instance` dari pola umum tetap layak dilaporkan; novelty menilai kebaruan, bukan nilai laporan.
- Writeup serupa bisa memakai istilah berbeda (naming drift) — cari dengan sinonim teknik, bukan hanya nama temuan.
- Referensi eksternal bisa membahas varian yang lebih lemah — bedakan cakupan referensi dari temuan aktual.
- Ketidaklengkapan knowledge base lokal memicu over-klaim kebaruan — catat keterbatasan cakupan, jangan simpulkan dari kekosongan.

## Severity Guidance

- Skill ini tidak menetapkan severity teknis temuan — severity ditetapkan pada tahap validasi/pelaporan.
- Yang dinilai di sini: keyakinan klasifikasi. Rationale dengan sumber kuat → keyakinan tinggi; penilaian berbasis kekosongan sumber → keyakinan rendah dan wajib dicatat demikian.
- Kombinasi `potentially-unknown` + high impact memicu alur §28 penuh — perlakukan sebagai kondisi stop, bukan sorotan menarik.

## Stop Conditions

- Finding belum tervalidasi → kembalikan ke `vulnerability-validation`; jangan klasifikasikan dugaan.
- Klasifikasi berdegak di antara dua tingkat dengan bukti yang setara → pilih konservatif, catat ambiguitas, eskalasi ke human.
- Indikasi `potentially-unknown` pada temuan high-impact → terapkan alur §28: stop active testing, evidence minimum, redact, inform user, tunggu keputusan human.
- Diminta "buktikan ini zero-day" → tolak kerangkanya; jelaskan batas §28 dan tawarkan klasifikasi berbasis bukti.

## Output Format

- Baris classification: `classification: <nilai §28>` + satu paragraf rationale (kriteria class/instance/variation + sumber).
- Tabel pembanding: referensi, kesamaan, perbedaan, dan penilaian relevansinya terhadap temuan.
- Rekomendasi disclosure path per klasifikasi, misalnya: `known-common-pattern`/`publicly-disclosed` → laporkan sebagai temuan standar ke program; `target-specific-instance` → laporan program dengan konteks dampak spesifik; `novel-variant` → laporan program + tawarkan koordinasi vendor; `potentially-unknown` → jalur eskalasi §28 dan `responsible-disclosure` dengan persetujuan human.
- Daftar keterbatasan penilaian dan langkah verifikasi lanjutan yang disarankan.

## Related Skills

- `vulnerability-chaining` — rantai temuan yang kebaruannya dinilai sebagai kesatuan.
- `false-positive-analysis` — memastikan yang dinilai memang temuan, bukan noise.
- `responsible-disclosure` — jalur pelaporan setelah klasifikasi; tidak ada auto-publish.
- `evidence-handling` — kaidah evidence dan reference yang dirujuk dalam rationale.
- `security-reporting` — penulisan laporan yang memuat classification dan rationale.
