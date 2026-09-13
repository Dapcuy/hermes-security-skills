# References

Knowledge referensi statis hasil **kurasi manusia**: dokumen OWASP, entri CWE,
catatan CVE, dan vendor advisories. Direktori ini adalah bagian dari lapisan
canonical knowledge (ROADMAP §27) dan struktur repo (ROADMAP §29) — tempat
pengetahuan umum yang sudah direview, bukan tempat data engagement.

## Struktur

```
references/
├── owasp/               panduan dan cheat sheet OWASP (pering kategori risiko)
├── cwe/                 entri CWE: kelas kelemahan dan sinyal deteksinya
├── cve/                 catatan CVE relevan: kondisi rentan, versi, mitigasi
└── vendor-advisories/   advisory resmi vendor (framework, server, library)
```

Empat subdirektori sengaja dibuat kosong (diisi `.gitkeep`) — konten masuk
bertahap lewat kurasi yang direview, bukan hasil import massal tanpa provenance.

## Format Entry Reference

Satu file markdown per entri, penamaan kebab-case (mis. `owasp/api-top10-bola.md`,
`cwe/cwe-639-authorization-bypass.md`). Setiap entri wajib memuat field knowledge
entry sesuai ROADMAP §27:

| Field | Isi |
|---|---|
| Definisi | Apa masalahnya, dirumuskan netral terhadap target tertentu. |
| Detection signal | Sinyal apa yang mengindikasikan kelas masalah ini (pola respons, struktur error, indikator konfigurasi) — dijabarkan sebagai kriteria observasi, bukan langkah serangan. |
| Preconditions | Kondisi yang harus ada supaya masalah ini mungkin muncul (fitur, versi, konfigurasi, konteks akses). |
| Validation method | Cara memvalidasi secara controlled: capability apa yang relevan, evidence apa yang membedakan true vs false. Metodologi dan kontrak evidence — bukan resep payload mentah. |
| Evidence requirement | Bukti minimum yang harus dikumpulkan sebelum finding naik state (ROADMAP §25, §26). |
| False positive | Penyebab false positive yang khas untuk kelas ini dan cara menyingkirkannya. |
| Severity guidance | Panduan menentukan severity: faktor pendorong, faktor pereda, kisaran umum dengan syaratnya. |
| References | Sumber eksternal resmi (dokumen asli, advisory, entri komunitas tepercaya) dengan URL/tanggal akses. |
| Provenance | Siapa mengkurasi, dari sumber apa, kapan diambil — entri tanpa provenance tidak boleh dipercaya. |
| Confidence | Tingkat keyakinan terhadap entri (mis. `high` untuk panduan resmi yang stabil, `medium` untuk catatan yang masih berkembang). |
| Last reviewed | Tanggal review terakhir (`YYYY-MM-DD`) — dasar deteksi knowledge basi (stale detection). |

Kerangka minimum satu entri:

```markdown
# <Judul entri>

- provenance: <kurasi oleh siapa, dari sumber apa, kapan diambil>
- confidence: <low | medium | high>
- last_reviewed: <YYYY-MM-DD>

## Definisi
<dapat berupa paragraf pendek.>

## Detection Signal
<bullet kriteria observasi.>

## Preconditions
<bullet kondisi pra-syarat.>

## Validation Method
<bullet metodologi validasi controlled + kontrak evidence.>

## Evidence Requirement
<bullet bukti minimum.>

## False Positive
<bullet penyebab false positive khas.>

## Severity Guidance
<bullet faktor pendorong/pereda dan kisaran umum.>

## References
<bullet sumber eksternal + tanggal akses.>
```

## Aturan

- **Konten target tidak pernah menulis ke sini (ROADMAP §24, §27).** Data yang berasal dari target — respons HTTP, header, isi error, hasil capture — hanya boleh hidup di `memory/cases` dengan trust level `untrusted`. Jalur masuk `references/` hanyalah kurasi manusia yang direview.
- **Provenance dan `last_reviewed` wajib** di setiap entri; entri tanpa keduanya diperlakukan belum selesai dan tidak layak dirujuk skill.
- **Bukan tempat evidence engagement**: data kasus, artifact, dan hasil validasi tetap di case memory/evidence store — entri di sini bersifat umum dan bebas data target.
- **Bukan tempat credential**: nilai credential tidak pernah masuk repo, termasuk di entri mana pun (ROADMAP §23).
- Entri yang usang (sumber berubah, versi produk relevan sudah tidak ada) ditandai stale dan diarsipkan, tidak diam-diam diedit menghapus riwayat.
