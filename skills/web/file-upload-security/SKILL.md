---
name: file-upload-security
description: >
  Use when auditing upload features: assess how the server validates MIME
  type, extension, filename, and size; test strictly with benign files
  (text, placeholder image, dummy PDF); and derive storage exposure,
  overwrite, and execution potential from server behavior rather than by
  ever uploading shells, malware, or real execution payloads.
version: 0.1.0
risk: medium
---

# File Upload Security

## Purpose

- Menganalisis pipeline upload secara menyeluruh: validasi MIME, extension, filename (termasuk path traversal di nama file), ukuran, penyimpanan, penyajian, dan potensi eksekusi.
- Menegakkan aturan file uji: HANYA file benign (teks, image placeholder, PDF dummy) — tanpa pengecualian.
- Menilai potensi eksekusi dari perilaku server saat menyajikan file (content-type, path, disposition), bukan dari upload payload berbahaya.

## When To Use

- Fitur upload: avatar, lampiran, impor dokumen, media, atau impor CSV.
- Perlu memeriksa sanitasi filename dan validasi konten satu lapis demi satu lapis.
- Perlu menilai di mana file disimpan, bagaimana diakses, dan apakah bisa menimpa file lain.

## When Not To Use

- Authorization `pending` atau scope tidak mencakup endpoint upload dan penyajian file.
- Tidak ada izin menyimpan artifact di aplikasi target — banyak pemeriksaan butuh file tersimpan; batasi diri pada analisis validasi dari data terekam.
- Untuk menguji bypass scanner atau validator dengan sampel berbahaya — dilarang keras.
- Storage milik pihak ketiga yang di luar scope entry.

## Authorization Preconditions

- Status `granted` atau `offline-lab`; approval conditional untuk upload dan replay penyajian file (ROADMAP §8, §9).
- Semua file uji benign dan isinya didokumentasikan di evidence (hash + deskripsi) sehingga bisa diaudit.
- Upload yang memicu proses server-side berat (render, konversi) dibatasi budget ketat agar tidak membebani target.
- File uji yang tersimpan dibersihkan setelah pengujian bila fitur menyediakan penghapusan; jika tidak, sisa artifact dicatat di laporan.

## Required Context

- Inventaris fitur upload dari web-surface-mapping: field, tipe yang diklaim diizinkan, limit ukuran, dan jumlah file.
- Baseline upload file benign standar beserta responsnya (path, URL hasil, ID).
- Cara penyajian file: endpoint publik atau private dan header penyajian yang terekam (content-type, disposition).
- Indikasi validator yang terlihat: pesan penolakan, magic-byte check, re-encode, scanner antivirus.
- Struktur path yang tampak dari respons atau history untuk analisis traversal.

## Required Capabilities


- `inspect_request` — membedah multipart request: field, content-type, nama file, dan struktur body.
- `request_replay` — mengulang upload dengan satu variasi uji per iterasi (mismatch header, extension ganda, nama file traversal).
- `response_comparison` — membandingkan penolakan atau penerimaan antar variasi dan perilaku penyajian antar file.
- Skill tidak menentukan provider; upload aktif hanya berjalan di provider proxy dalam approval (ROADMAP §4.1, §5.2).

## Core Concepts

- **Layer validasi**: klaim klien (content-type header), magic bytes, extension, re-encoding, dan aturan bisnis — lemahnya satu layer belum berarti lemah menyeluruh; catat layer mana yang bekerja.
- **Filename adalah input**: sanitasi nama (normalisasi, penggantian karakter) dan traversal di nama file (segment naik direktori, absolute path, unicode) diperlakukan seperti parameter lain.
- **Penyajian menentukan dampak**: file tersimpan hanya berbahaya bila bisa dijangkau dan disajikan dalam konteks yang dieksekusi (content-type aktif, inline); Content-Disposition attachment dan storage private memangkas dampak.
- **Polyglot sebagai analisis teori**: struktur file yang valid bagi dua parser dianalisis dari validator yang terlihat; pengujian hanya dengan polyglot benign (image plus teks) — tanpa wrapper eksekusi.
- **Overwrite dan kontrol path**: nama file yang sama menimpa file lama atau path hasil yang bisa diarahkan — dinilai dari perilaku penyimpanan, satu variasi per iterasi.
- **Bukti dari perilaku, bukan dari payload**: potensi eksekusi disimpulkan dari extension yang di-serve, content-type aktif, path disclosure di webroot, dan pemrosesan server-side — tanpa pernah mengunggah shell.

## Reasoning Workflow

1. Petakan fitur upload dan tipe yang diizinkan; rekam baseline upload file benign standar.
2. Uji validasi satu per satu: content-type mismatch, extension berbahaya pada isi benign, double extension, karakter khusus di nama — satu variasi per iterasi.
3. Uji filename: traversal path, nama file yang sudah ada (overwrite), nama sangat panjang atau karakter unicode.
4. Setelah upload berhasil, ambil file lewat penyajian yang ada dan catat header penyajian: content-type, disposition, cache.
5. Analisis hasil: di mana file disimpan, siapa yang bisa mengakses, dan apakah konteks penyajian bisa mengeksekusi.
6. Untuk polyglot, analisis teori validator; bila perlu diuji, gunakan polyglot benign dan nyatakan isinya di evidence.
7. Jalankan FP check; susun narasi dampak; perbarui lifecycle (ROADMAP §26).

## Allowed Operations

- Upload file benign (teks, image placeholder, PDF dummy) dengan satu variasi per iterasi, dalam budget approval.
- Pengambilan ulang file yang diupload melalui penyajian normal untuk membaca header penyajian.
- Penghapusan file uji bila fitur menyediakannya.
- Analisis statis respons, path, dan header dari data terekam.

## Approval Requirements

- Upload ber-risk MEDIUM → approval conditional scoped per endpoint; upload yang memicu konversi atau render server-side berat dievaluasi ulang (ROADMAP §8, §9).
- Approval mencakup endpoint upload DAN endpoint penyajian file yang akan diuji.
- Budget ketat: jumlah file terbatas, tanpa pengulangan massal.
- Approval kadaluarsa atau dicabut → berhenti; sisa artifact dilaporkan (ROADMAP §9, §10).

## Forbidden Operations

- Upload web shell, malware, macro aktif, payload eksekusi nyata, atau mekanisme persistence — dilarang keras dalam kondisi apa pun.
- File berukuran besar untuk menguji limit secara DoS, atau arsip bom.
- Upload yang memicu pemrosesan server-side berulang atau berat tanpa persetujuan budget.
- Menyimpan file uji pada konteks yang terekspos user lain tanpa pembersihan.
- Menyimpulkan eksekusi dengan mengklaim payload "berhasil jalan" tanpa bukti penyajian — bukti eksekusi hanya dari perilaku server yang terekam.

## Evidence Requirements

- Minimum set ROADMAP §25: baseline evidence, reproduction steps, expected behavior, actual behavior, impact, false-positive analysis, scope reference, confidence, sanitized artifact.
- Deskripsi tiap file uji: nama, ukuran, hash, isi ringkas — dapat diaudit ulang.
- Respons upload dan header penyajian tiap file: content-type, disposition, path atau URL hasil.
- Bukti pembersihan artifact atau catatan sisa file di akhir pengujian.

## False Positive Checks

- File ditolak oleh scanner antivirus atau validator khusus, bukan oleh lapisan yang sedang diuji — bedakan lapisan penolakannya dari pesan respons.
- Storage private: file tersimpan tetapi tidak bisa diakses publik — dampak terbatas; jangan menyamakan penyimpanan dengan eksposur.
- Extension disajikan sebagai unduhan (Content-Disposition attachment) atau content-type netral — konteks penyajian tidak mengeksekusi.
- Nama file otomatis di-generate server (uuid/acak) — traversal di nama file tidak pernah mencapai filesystem.
- Respons sukses upload tanpa file benar-benar diproses — verifikasi keberadaan file lewat penyajian sebelum menyimpulkan lolos validasi.

## Severity Guidance

- File yang dikendalikan penyerang disajikan inline dengan content-type aktif di origin utama → tinggi (potensi eksekusi dianalisis dari perilaku penyajian).
- Path traversal di filename yang mengubah lokasi penyimpanan → tinggi, tergantung kemampuan menulis di luar direktori yang dimaksud.
- Overwrite file fungsional aplikasi atau data → tinggi; rendah bila namespace terisolasi per user.
- Upload lolos validasi tetapi storage private dan disajikan sebagai unduhan → rendah hingga sedang (integritas dan penyalahgunaan, bukan eksekusi).

## Stop Conditions

- Server menunjukkan pemrosesan tidak terduga (error konversi berulang, antrean menumpuk) → stop upload berikutnya (ROADMAP §10).
- File uji ternyata terekspos ke user lain → berhenti, bersihkan, laporkan.
- Repeated 5xx pada endpoint upload → stop (ROADMAP §10).
- Budget habis, approval dicabut, atau authorization expired → stop; laporkan sisa artifact.

## Output Format

- Profil validasi per endpoint: layer yang aktif (header, magic byte, extension, ukuran) dan variasi yang lolos atau ditolak.
- Profil penyajian: lokasi storage, konteks akses, header penyajian, potensi eksekusi yang dianalisis.
- Daftar artifact uji beserta status pembersihan dan referensi evidence (hash + path).

## Related Skills

- `web-surface-mapping` — inventaris fitur upload.
- `http-request-replay`, `http-response-comparison` — operasi inti yang dipakai.
- `security-misconfiguration` — konfigurasi penyajian file dan header keamanan.
- `controlled-fuzzing` — input variation terkontrol setelah pipeline upload dipahami.
- `false-positive-analysis`, `vulnerability-validation` — triase dan lifecycle finding.
- `evidence-handling` — penanganan artifact dan sanitasi (ROADMAP §25).
