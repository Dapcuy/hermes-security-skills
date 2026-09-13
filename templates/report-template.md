# Security Report Template

> Template security report untuk draft laporan temuan (ROADMAP §2 in-scope:
> report generation; §25: evidence-based). Semua klaim dalam laporan harus
> tertaut ke finding dan evidence yang sudah divalidasi — laporan bukan tempat
> memperbesar klaim.

## Peringatan Submission

**Pengiriman otomatis tanpa persetujuan manusia adalah non-goal project
(ROADMAP §2).** Report yang dihasilkan skill selalu berstatus draft: pengiriman
ke program bug bounty, vendor, atau kanal publik apapun menunggu human approval
dan mengikuti alur `responsible-disclosure`. Tidak ada auto-publish, tidak ada
automatic public disclosure.

## Aturan Pakai

- Satu report untuk satu finding (atau beberapa finding yang memang dilaporkan bersama — jelaskan pengelompokannya di summary).
- Hanya finding dengan state `confirmed` (atau yang pemilik engagement minta dilaporkan secara eksplisit) yang masuk report.
- Semua referensi evidence merujuk ID evidence yang sudah disanitasi (ROADMAP §23); nilai credential, session identifier asli, dan data pribadi tidak pernah masuk report.
- Ganti semua placeholder `<SEPERTI-INI>`; field yang belum bisa diisi ditandai eksplisit dengan alasan.
- Simpan draft report di case memory engagement; knowledge canonical tidak menyimpan data target.

## Template

```markdown
# <Jenis temuan> pada <komponen/target>

## Header

- Report ID: <RPT-XXXX>
- Title: <jenis temuan + lokasi, satu baris>
- Severity: <info | low | medium | high | critical>
- Status: <draft | ready-for-review | approved-by-human | submitted | duplicate | closed>
- Date: <YYYY-MM-DD>
- Finding Ref: <FND-XXXX>
- Case Ref: <CASE-XXXX>

## Summary

<ringkasan 2-5 kalimat: apa temuannya, di mana, dampaknya, dan status validasinya.>

## Affected Scope

- <host/path/endpoint/versi yang terdampak, satu per baris>
- scope_ref: <scope entry / authorization record>

## Reproduction Steps

1. <langkah, cukup rinci untuk diulang tim triage program tanpa konteks tambahan>
2. <langkah berikutnya>
3. <...>

## Evidence References

- <ID evidence — keterangan singkat, mis. "EVD-0031 — respons 200 pada percobaan akses lintas akun">

## Impact

<dampak dari sudut pandang pemilik target: siapa terdampak, data/aksi apa,
skenario penyalahgunaan realistis. Tanpa dramatisasi.>

## Remediation

<rekomendasi perbaikan konkret dan terurut: kontrol yang harus ada, cara
memverifikasi perbaikan. Bila ada beberapa opsi, sebutkan trade-off singkatnya.>

## References

- <referensi publik relevan: entri CWE/CVE/advisory, dokumentasi, entri knowledge internal — ID saja bila internal>
```

## Panduan Pengisian

| Field | Instruksi singkat |
|---|---|
| Header `Title` | Kalimat tunggal yang membuat triage langsung paham: jenis kerentanan + komponen + kondisi singkat. |
| Header `Severity` | Selaras dengan `severity_provisional` finding dan Severity Guidance skill sumber; jelaskan dasar penilaian di Impact bila nilainya berbeda dari klaim awal. |
| Header `Status` | `draft` sampai human memutuskan; `submitted` hanya boleh terisi SETELAH persetujuan human tercatat (ROADMAP §2, §9). |
| `Summary` | Berdiri sendiri tanpa context repo; sebutkan status validasi (reproduced/confirmed) agar triage tahu laporan ini evidence-based, bukan dugaan. |
| `Affected Scope` | Eksplisit per host/path/versi — jangan wildcard bila cakupan sebenarnya lebih sempit; sertakan `scope_ref` sebagai bukti pengujian berada di dalam authorization. |
| `Reproduction Steps` | Salin dari `reproduction_steps` finding, dirapikan untuk pembaca eksternal: prasyarat akun, urutan request, hasil per langkah. Bila langkah sensitif (mis. berisi akun test), anonimkan tanpa mengurangi reproducibility. |
| `Evidence References` | Daftar ID evidence pendukung dengan keterangan per baris; semua sudah disanitasi. Body besar dirujuk, bukan ditempel. |
| `Impact` | Konkret dan terukur; hubungkan ke aset bisnis, bukan ke payload. Klaim berantai (chaining) hanya disebut bila sudah dibuktikan lewat finding tersendiri. |
| `Remediation` | Aksi yang bisa dieksekusi tim engineering target, bukan teori umum; sertakan cara memverifikasi perbaikan bila memungkinkan. |
| `References` | Sumber eksternal yang membantu triage (class CWE, advisory, dokumentasi resmi); pastikan referensi internal tetap ID, bukan isi kasus. |

## Checklist Sebelum Draft Diserahkan ke Human

- [ ] Semua placeholder sudah diganti; tidak ada field kosong tanpa penjelasan.
- [ ] Finding terkait berstate `confirmed` dan minimum evidence ROADMAP §25 lengkap.
- [ ] Semua evidence reference tersanitasi dan valid (hash/path sesuai).
- [ ] Tidak ada credential, session identifier asli, atau data pribadi di dalam teks maupun artifact.
- [ ] Status masih `draft` atau `ready-for-review` — bukan `submitted`.
- [ ] Human approval sudah diminta dan dicatat sebelum status berubah menjadi `submitted` (ROADMAP §2).
