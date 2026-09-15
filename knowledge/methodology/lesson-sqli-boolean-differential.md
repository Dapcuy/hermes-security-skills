---
id: lesson-sqli-boolean-differential
title: Validasi SQL Injection via Boolean Differential
category: injection-analysis
source: juice-shop-engagement
confidence: 0.9
state: reviewed
last_reviewed: 2026-09-13T10:54:40Z
provenance:
  source: juice-shop-engagement-2026-09-13
  trust: trusted
---


> Catatan relokasi v3.0 (2026-09-13): entry dipindah dari
> `memory/cases/juice-demo/` ke `knowledge/methodology/` sesuai ROADMAP
> v3.0 §23–§24 — direktori `memory/` dihapus sebagai komponen utama dan
> diganti Knowledge Base curated; state kasus kini hidup di evidence +
> jobs + approval + events. State dikembalikan ke `reviewed` (direktori
> ini curated manual, diisi lewat keputusan owner). Provenance asli
> dipertahankan.
>
> Riwayat relokasi sebelumnya: `knowledge/reviewed/` →
> `memory/cases/juice-demo/` (2026-09-13, alasan: dianggap pelajaran
> spesifik-kasus; keputusan tersebut diputanarkan kembali saat v3.0).

Pelajaran dari engagement Juice Shop: payload klasik `--` bisa berubah
jadi error 500 di versi app baru. Metode yang lebih tahan versi:
boolean differential — bandingkan `q=' AND 1=1 AND name LIKE '` (harus
kembalikan katalog penuh) vs `q=' AND 1=2 AND name LIKE '` (harus 0 item).
Satu-satunya perbedaan literal boolean + perbedaan hasil = bukti input
dieksekusi sebagai logika SQL. Error disclosure (`SQLITE_ERROR: incomplete
input`) dipakai sebagai temuan sekunder untuk enumerasi kolom.
