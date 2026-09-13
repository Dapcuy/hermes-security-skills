# Finding Template

> Template draft finding sesuai ROADMAP §25 (minimum evidence) dan §26 (finding
> lifecycle). Nama field disamakan dengan `schemas/finding.schema.json` agar
> template dan schema tidak drift. Payload yang "berhasil" bukan konfirmasi
> vulnerability (ROADMAP §22) — finding hanya naik state bila evidence
> mendukung, bukan karena indikasi tunggal.

## Aturan Pakai

- Setiap finding selalu dibuka pada state `observation` atau `hypothesis`; tidak pernah membuka finding langsung di `confirmed`.
- Finding tidak boleh `confirmed` hanya berdasarkan satu indikasi — minimum evidence ROADMAP §25 (baseline, reproduction, expected/actual, impact, false-positive analysis, scope reference, confidence, sanitized artifact) wajib terpenuhi sebelum naik state.
- Semua referensi evidence merujuk ID evidence yang SUDAH disanitasi terhadap credential aktif (ROADMAP §23) — jangan tempel nilai sensitif langsung ke dalam template.
- Placeholder ditulis dalam sudut `<SEPERTI-INI>`; ganti semua placeholder sebelum finding dianggap lengkap. Field yang memang belum bisa diisi ditandai eksplisit dengan alasan, bukan dikosongkan diam-diam.
- Temuan berpotensi novel mengikuti alur ROADMAP §28: stop active testing, simpan evidence minimum, redact data sensitif, tandai `potentially-unknown`, inform user — human yang memutuskan langkah berikutnya.
- Simpan hasil pengisian sebagai bagian case memory engagement, bukan di knowledge canonical.

## Template

Salin blok di bawah ini sebagai draft finding baru, lalu isi per field mengikuti panduan pengisian di bagian akhir dokumen.

```markdown
# Finding <FND-XXXX>: <judul singkat satu kalimat>

## Metadata

- finding_id: <FND-XXXX>
- case_id: <CASE-XXXX>
- state: <observation | hypothesis | suspected | needs-validation | reproduced | confirmed | duplicate | rejected | inconclusive>
- severity_provisional: <info | low | medium | high | critical>
- novelty_classification: <known-common-pattern | target-specific-instance | novel-variant | potentially-unknown | under-review | vendor-notified | confirmed-by-vendor | publicly-disclosed>
- date_opened: <YYYY-MM-DD>
- date_updated: <YYYY-MM-DD>

## Hypothesis

<dinyatakan sebagai hypothesis keamanan yang bisa diuji, bukan kesimpulan.>

## Baseline Evidence

- baseline_evidence_ref: <ID evidence baseline>

## Reproduction Steps

1. <langkah pertama, cukup spesifik untuk diulang orang lain>
2. <langkah berikutnya>
3. <...>

## Expected vs Actual

- expected_behavior: <perilaku yang seharusnya terjadi bila kontrol bekerja benar>
- actual_behavior: <perilaku yang teramati pada evidence>

## Impact

<dampak konkret bila vulnerability valid.>

## False Positive Analysis

<alternatif penyebab yang dipertimbangkan dan mengapa dikesampingkan.>

## Scope Reference

- scope_ref: <scope entry / authorization record>

## Confidence

- confidence: <0.0 - 1.0>

## Sanitized Artifacts

- <path artifact yang sudah disanitasi>

## State History

- <YYYY-MM-DD> — <state> — <alasan perpindahan state + referensi evidence>
```

## Panduan Pengisian

| Field | Instruksi singkat |
|---|---|
| `finding_id` | Identifier unik konsisten dengan penomoran case (mis. `FND-0007`); dipakai report dan state history untuk merujuk finding ini. |
| `case_id` | Case engagement pemilik finding; mengikat finding ke scope dan authorization record yang sama. |
| `state` | Lifecycle ROADMAP §26: `observation -> hypothesis -> suspected -> needs-validation -> reproduced -> confirmed`; jalur alternatif `duplicate`, `rejected`, `inconclusive`. Isi SATU nilai saat ini; riwayat perpindahan dicatat di State History. |
| `severity_provisional` | Nilai awal yang bisa berubah; final dijabarkan saat report. Gunakan Severity Guidance dari skill yang menemukan masalah, jangan menebak dari nama endpoint. |
| `novelty_classification` | Klasifikasi ROADMAP §28, mulai dari `known-common-pattern` atau `target-specific-instance`. `potentially-unknown` hanya lewat alur §28 (stop, redact, inform user, human decides); jangan pernah otomatis menyatakan zero-day. |
| `hypothesis` | Rumusan yang bisa diuji benar/salah, ditulis SEBELUM pengujian (dari hypothesis-management). Hindari kalimat kesimpulan seperti "aplikasi rentan" — tulis kondisi yang diduga, mis. "server tidak memvalidasi kepemilikan objek pada endpoint X". |
| `baseline_evidence_ref` | ID evidence kondisi NORMAL sebelum pengujian (mis. respons standar akun-A terhadap objek miliknya). Baseline wajib ada sebelum klaim perbedaan; tanpa baseline, actual behavior tidak bisa dinilai menyimpang. |
| `reproduction_steps` | Langkah berurutan yang bisa diulang reviewer lain tanpa konteks tambahan: prasyarat (akun/role), request yang relevan, dan hasil tiap langkah. Wajib lengkap sebelum state `reproduced`. |
| `expected_behavior` | Perilaku yang seharusnya terjadi bila kontrol keamanan bekerja (mis. ditolak dengan 403, nilai tidak berubah). Sumbernya kebijakan/spesifikasi, bukan hasil pengamatan. |
| `actual_behavior` | Perilaku yang benar-benar teramati, dirujuk ke evidence. Tulis apa yang terlihat, bukan interpretasi; interpretasi masuk ke impact dan false-positive analysis. |
| `impact` | Dampak konkret bila valid: siapa yang terdampak, data/aksi apa yang terekspos, skenario penyalahgunaan realistis. Hindari dramatisasi dan klaim berantai yang belum dibuktikan. |
| `false_positive_analysis` | Wajib untuk SEMUA state (ROADMAP §46). Daftar alternatif penyebab: cache, environment yang berbeda, timing/koincidensi, artefak tool, konfigurasi lab — dan bukti mengapa masing-masing dikesampingkan. Bila tidak bisa dikonfirmasi, state turun ke `inconclusive`, bukan dipaksakan naik. |
| `scope_ref` | Scope entry atau authorization record yang mengizinkan pengujian ini. Finding tanpa scope_ref yang sah tidak sah — targets out-of-scope membuat seluruh temuan batal. |
| `confidence` | Angka 0.0–1.0 beserta alasan satu kalimat. Naik hanya saat evidence bertambah (reproduksi ulang, baseline banding), bukan karena keyakinan subjektif. |
| `sanitized_artifacts` | Path artifact yang sudah lolos sanitasi credential aktif SEBELUM dipersist (ROADMAP §23, §25). Referensikan hasil sanitasi, bukan dump mentah; raw body besar disimpan sebagai evidence reference, bukan diinline ke sini. |
| State History | Entri append-only per perpindahan state: tanggal, state baru, alasan, dan referensi evidence pendukung. Jangan menimpa riwayat lama — perpindahan yang bisa dipertanggungjawabkan adalah bagian dari evidence. |

## Pengingat

- `confirmed` adalah state yang mahal: pastikan semua field minimum §25 terisi dan false-positive analysis menutup alternatif utama sebelum mencapainya.
- Finding `duplicate` dan `rejected` tetap dipertahankan beserta alasannya — mereka mencegah pengujian ulang yang sia-sia di engagement berikutnya.
- Submission ke program/vendor tidak otomatis dari finding: template report dan alur disclosure punya gerbang human approval tersendiri (ROADMAP §2).
