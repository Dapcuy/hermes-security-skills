# knowledge/false-positives/

Katalog pola false positive (ROADMAP v3.0 §23): perilaku WAF, error
message generik, anomali timing, reflection tanpa eksekusi, perbedaan
autentikasi tanpa celah otorisasi, dsb.

- Siapa yang menulis: owner/maintainer — direktori curated manual, diisi
  lewat commit + review dari pelajaran engagement yang sudah divalidasi.
- Isi yang sah: entry knowledge berformat markdown+frontmatter (lihat
  `../README.md`) yang menjelaskan sinyal, mengapa itu false positive,
  dan cara memverifikasinya.
- Tujuan: bahan untuk skill `false-positive-analysis` dan reasoning
  Hermes — mengurangi temuan palsu, bukan menggantikan validasi.
- Provenance: wajib `provenance.trust: trusted`; konten target tidak
  pernah menulis di sini (§20).
