# knowledge/research/

Hasil ingest (`hermes-security knowledge ingest`) — entry state
`captured|normalized|proposed` yang MENUNGGU human review (ROADMAP v3.0
§23).

- Siapa yang menulis: control plane, lewat `knowledge ingest` (input file
  ditulis manusia).
- Isi yang sah: draf pengetahuan berprovenance manusia (research notes,
  pola baru, pengamatan menarik) — frontmatter wajib lengkap.
- Provenance: `provenance.source` TIDAK BOLEH `target-controlled` dan
  `trust` TIDAK BOLEH `untrusted` — ingest menolaknya fail-closed (§20);
  konten target hidup di evidence, bukan di sini.
- Jalur keluar: `knowledge review <id> --state reviewed` → `../reviewed/`;
  promosi ke canonical adalah keputusan owner.
