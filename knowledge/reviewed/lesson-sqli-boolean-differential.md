---
id: lesson-sqli-boolean-differential
title: Validasi SQL Injection via Boolean Differential
category: injection-analysis
source: juice-shop-engagement
confidence: 0.9
state: reviewed
last_reviewed: 2026-09-13T10:54:40Z
expires_at: 2027-09-13T00:00:00Z
provenance:
  source: juice-shop-engagement-2026-09-13
  trust: trusted
---


Pelajaran dari engagement Juice Shop: payload klasik `--` bisa berubah
jadi error 500 di versi app baru. Metode yang lebih tahan versi:
boolean differential — bandingkan `q=' AND 1=1 AND name LIKE '` (harus
kembalikan katalog penuh) vs `q=' AND 1=2 AND name LIKE '` (harus 0 item).
Satu-satunya perbedaan literal boolean + perbedaan hasil = bukti input
dieksekusi sebagai logika SQL. Error disclosure (`SQLITE_ERROR: incomplete
input`) dipakai sebagai temuan sekunder untuk enumerasi kolom.
