---
name: payload-selection
description: >
  Use when a controlled test needs payloads chosen before execution: select
  entries by parameter context, risk, and request budget, attach the required
  payload metadata, and enforce the payload policy defaults so destructive,
  exfiltration, and credential-attack lists never reach an execution plan.
version: 0.1.0
risk: medium
---

# Payload Selection

## Purpose

- Menyediakan metodologi pemilihan payload berdasarkan context, risk, dan request budget sebelum payload masuk execution plan (ROADMAP §22).
- Menegakkan payload metadata wajib: setiap entry membawa `id`, `category`, `context`, `risk`, `destructive`, `max_attempts`, dan `source`; tanpa metadata lengkap, payload tidak lolos.
- Menjaga default guardrail MVP: hanya payload dengan `destructive: false`, tanpa exfiltration, tanpa credential attack list (ROADMAP §22).

## When To Use

- Sebuah hypothesis butuh input variation terkontrol terhadap parameter tertentu dan kandidat payload harus dipilih.
- Sebelum controlled-fuzzing atau injection-validation menyusun iterasi, agar eksekusi memakai payload set yang sudah lolos kurasi.
- Saat daftar kandidat payload harus dipangkas agar muat dalam request budget approval yang aktif.

## When Not To Use

- Skill ini tidak mengeksekusi payload — eksekusi selalu lewat replay di skill validasi yang meminta capability.
- Authorization masih `pending` — pemilihan boleh berjalan sebagai reasoning, tetapi jangan persiapkan eksekusi apa pun.
- Bukan untuk menyusun wordlist massal tanpa konteks parameter; daftar tanpa target dan tanpa metadata adalah pemborosan dan risiko.

## Authorization Preconditions

- Pemilihan payload murni reasoning dan tidak mengirim traffic ke target, sehingga tidak ada precondition jaringan.
- Payload set yang dihasilkan hanya boleh ditujukan untuk target yang berada di dalam scope entry yang sah.
- Eksekusi menyusul lewat skill validasi dengan approval tersendiri; payload set bukan pengganti approval.
- Payload destructive, exfiltration, atau credential attack list tidak dipilih dalam kondisi apa pun pada MVP (ROADMAP §22: deny).

## Required Context

- Parameter target: nama, lokasi (query, body, header), tipe data, dan konteks parsing (string, numeric, JSON, XML, URL-encoded).
- Baseline request/response untuk parameter tersebut, sebagai pembanding saat eksekusi nanti.
- Request budget yang tersedia: sisa budget approval aktif atau estimasi approval yang akan diajukan.
- Kebijakan payload yang berlaku pada engagement, termasuk batas jumlah entry per task dan total request.

## Required Capabilities

- `inspect_request` — membaca request yang sudah terekam di event store untuk menentukan konteks parameter sebelum payload dipilih.
- Capability ini read-only dan tidak mengirim traffic ke target; konteks parameter cukup dinilai dari data terekam.
- Skill tidak menentukan provider — pemilihan provider dilakukan capability registry (ROADMAP §4.1, §5).
- Capability eksekusi (replay) diminta oleh skill validasi, bukan oleh skill ini; payload set yang dihasilkan hanyalah persiapan.

## Core Concepts

- **Metadata wajib**: setiap payload membawa `id`, `category`, `context`, `risk`, `destructive`, `max_attempts`, dan `source: curated` (ROADMAP §22).
- **destructive=false untuk MVP**: payload yang mengubah/menghapus data, mengekstrak data, atau menyerang kredensial tidak pernah dipilih.
- **Context matching**: payload string tidak otomatis cocok untuk konteks JSON atau numeric; konteks parsing parameter menentukan kandidat yang relevan.
- **Budget-first selection**: jumlah payload dipangkas agar total request muat dalam batas per task dan total request yang berlaku (ROADMAP §22).
- **Payload success != vulnerability confirmation**: payload yang "berhasil" tetap observation; WAF bypass pun bukan vulnerability (ROADMAP §22).

## Reasoning Workflow

1. Identifikasi parameter yang diuji dan konteks parsing-nya dari request terekam lewat `inspect_request`.
2. Tentukan kategori payload yang relevan dengan hypothesis — bukan seluruh katalog.
3. Filter kandidat berdasarkan metadata: `destructive: false`, risk sesuai approval, dan `max_attempts` yang masuk akal.
4. Pangkas daftar ke budget: hitung estimasi request per payload dan sisihkan entry prioritas rendah sampai total muat.
5. Lampirkan metadata lengkap pada setiap entry yang lolos, lalu serahkan payload set ke skill eksekusi.
6. Catat payload yang disisihkan beserta alasannya di case memory untuk pembelajaran engagement.

## Allowed Operations

- Memilih, memangkas, dan menganotasi payload dari sumber curated berdasarkan konteks parameter.
- Menolak payload yang tidak membawa metadata lengkap atau yang konteksnya tidak cocok.
- Merekomendasikan urutan eksekusi berdasarkan risk terendah dan informasi yang paling diskriminan lebih dulu.

## Approval Requirements

- Skill ini tidak mengeksekusi apa pun, sehingga tidak mengurus approval sendiri; approval diurus skill yang menjalankan replay.
- Payload set yang diserahkan wajib muat dalam budget approval yang ada; bila tidak, ajukan approval baru — jangan melebarkan daftar diam-diam.
- Bila payload terbaik menyentuh method stateful (POST/PUT/PATCH/DELETE), sifatkan eksekusinya sebagai risk HIGH yang butuh approval eksplisit di skill validasi (ROADMAP §8).

## Forbidden Operations

- Memilih payload destructive, exfiltration, atau credential attack list — semuanya deny pada MVP (ROADMAP §22).
- Menyuntikkan payload tanpa metadata ke execution plan.
- Memperbesar daftar payload melampaui budget tanpa approval baru.
- Menyatakan vulnerability hanya karena sebuah payload "sukses" (ROADMAP §22).

## Evidence Requirements

- Catat payload set final: `id`, `category`, `context`, `risk`, flag `destructive`, `max_attempts`, dan `source` per entry.
- Catat payload yang disisihkan beserta alasan penyisihannya.
- Kaitkan payload set dengan hypothesis asal dan budget yang direncanakan, agar eksekusi nanti bisa diaudit.

## False Positive Checks

- Apakah konteks parameter salah baca (mis. numeric dibaca string) sehingga payload yang dipilih tidak relevan?
- Apakah perubahan respons yang diharapkan sebenarnya akan berasal dari WAF challenge, bukan efek payload di server?
- Apakah ada payload duplikat dalam set yang membuat estimasi budget terlihat lebih besar dari kenyataan?
- Apakah payload sudah kedaluwarsa untuk versi aplikasi sekarang (parameter berubah nama/lokasi)?

## Severity Guidance

- Payload tidak memiliki severity; severity lahir dari dampak vulnerability yang tervalidasi, bukan dari agresivitas payload.
- Pemilihan payload yang konservatif tidak menurunkan severity temuan yang sah — ia hanya menjaga safety.
- Bila satu-satunya cara "menaikkan dampak" adalah memakai payload yang lebih berbahaya, itu sinyal untuk memperkuat evidence, bukan untuk melonggarkan kurasi.

## Stop Conditions

- Tidak ada payload curated yang cocok dengan konteks parameter dan budget → hentikan persiapan dan laporkan gap, jangan memaksakan payload generik.
- Satu-satunya kandidat relevan adalah payload destructive → stop; payload itu tidak dipilih.
- Budget approval tidak mencukupi satu iterasi bermakna → minta approval baru atau tunda eksekusi (ROADMAP §10).

## Output Format

- Payload set terpilih: daftar entry dengan metadata lengkap per payload (id, category, context, risk, destructive, max_attempts, source).
- Ringkasan budget: estimasi request per entry dan total dibanding batas approval.
- Daftar penyisihan beserta alasannya.

## Related Skills

- `controlled-fuzzing` — eksekusi terkontrol atas payload set ini.
- `injection-validation` — validasi indikasi injection memakai payload terkurasi.
- `vulnerability-validation` — alur validasi umum baseline → replay → bandingkan.
- `false-positive-analysis` — penyisiran indikasi setelah eksekusi.
