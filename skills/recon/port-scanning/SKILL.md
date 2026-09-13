---
name: port-scanning
description: >
  Use when an explicitly approved, in-scope host needs TCP port enumeration
  via the nmap_scan capability, restricted to the connect scan method and
  the exact port range and host list written in a scoped approval. Port
  scanning is high risk: many bug bounty programs prohibit it entirely.
version: 0.1.0
risk: high
---

# Port Scanning

## Purpose

- Mengenumerasi port TCP pada host in-scope melalui capability `nmap_scan`, dengan metode connect scan (`-sT`) dan port range yang dibatasi persis oleh approval eksplisit (ROADMAP §8, §9, §13.1).
- Menghasilkan observation port terbuka/tertutup/terfilter per host sebagai bahan pemetaan layanan untuk attack-surface-prioritization — bukan sebagai kesimpulan kerentanan.
- Menjaga operasi berisiko tinggi ini tetap dalam korset sempit: satu metode paling tidak invasif, satu jalur capability, nol improvisasi (ROADMAP §13.1).
- Membuat batas program menjadi penentu: banyak program bug bounty melarang port scanning; skill ini tidak pernah berjalan melawan larangan itu.

## When To Use

- Program terms secara eksplisit mengizinkan port scanning, host in-scope sudah ditetapkan, dan approval scoped untuk scanning sudah aktif (ROADMAP §9).
- Pemetaan layanan dibutuhkan untuk melengkapi attack-surface-prioritization dan tidak ada cara pasif yang memadai.
- User secara eksplisit meminta enumerasi port atas host tertentu dan menyediakan approval untuk itu.
- Hasil technology-probing atau recon lain menunjukkan host in-scope yang layak dipetakan portnya dalam batas approval.

## When Not To Use

- Program terms diam atau melarang port scanning — kebanyakan program bug bounty melarang atau membatasi keras; tanpa izin eksplisit, skill ini tidak dijalankan (ROADMAP §13.1).
- Approval belum ada, sudah kadaluarsa, atau tidak mencantumkan host/port range yang diminta — tidak ada mode "sementara menunggu approval".
- Authorization tidak `granted`, atau host berada di luar scope entries (ROADMAP §8).
- Kebutuhan sebenarnya hanya memahami layanan dari traffic terekam — jalur pasif (history, technology-fingerprinting) selalu diutamakan lebih dulu.
- Target menunjukkan proteksi sensitif (tarpit, blokir massal) atau berada di lingkungan produksi yang rapuh — konsultasikan dulu, jangan memaksa.

## Authorization Preconditions

- Authorization status `granted` dan mencakup host yang discan; URL atau IP yang diberikan user tidak otomatis berarti authorization (ROADMAP §8).
- Approval scoped eksplisit WAJIB sudah aktif sebelum eksekusi, mencantumkan: host list, port range, metode connect scan, budget, dan expiration (ROADMAP §9).
- Scope validation wajib membatasi target ke host yang di-scope eksplisit; host yang hanya "terlihat tertaut" tidak ikut masuk (ROADMAP §8, §13.1).
- Program terms diperiksa dan dicatat: izin port scanning disebutkan secara eksplisit, bukan disimpulkan dari ketiadaan larangan.

## Required Context

- Host list in-scope yang sah beserta approval aktif yang menyebut host dan port range tersebut.
- Batasan program terms khusus scanning: rate, jendela waktu, teknik yang dilarang, dan kontak keamanan bila ada.
- Hasil recon sebelumnya (technology-probing, attack-surface-prioritization) yang menjadi dasar pemilihan host.
- Sisa budget dan riwayat interaksi dengan target yang sama (pernah diblokir, pernah 429, dsb.).

## Required Capabilities

- `nmap_scan` — enumerasi port TCP dengan metode connect scan; wrapper image menegakkan policy bundle, budget, dan rate limit dari execution plan (ROADMAP §13.1).
- Eksekusi hanya pada provider docker sesuai registry (ROADMAP §4.1); metode, host, dan port yang menolak policy ditolak fail-closed, bukan di-fallback (ROADMAP §5.1).
- Interpretasi hasil (layanan apa, risiko apa) adalah reasoning Hermes atas output capability — hasil scan adalah observation, bukan finding (ROADMAP §17, §26).

## Core Concepts

- **Connect scan (`-sT`) sebagai metode tunggal**: handshake TCP penuh tanpa raw packet — kompatibel dengan container `cap_drop: ALL` dan tidak butuh NET_RAW (ROADMAP §13.1).
- **Port range dari approval**: range yang boleh discan ditulis di approval; skill tidak pernah memperluasnya, termasuk "port umum saja kalau range-nya lama".
- **Tiga keadaan, tiga makna berbeda**: open, closed, dan filtered adalah observation mentah — filtered bisa firewall, bukan ketiadaan layanan.
- **Risk HIGH = approval_required**: kelas ini tidak pernah automatic; tanpa approval eksplisit, capability ditolak (policy/risk.yaml, ROADMAP §8).
- **Provenance wajib**: output capability mencatat tool, versi, dan parameter pemindaian sebagai bagian evidence (ROADMAP §13.1).

## Reasoning Workflow

1. Verifikasi rantai prasyarat: authorization `granted`, program terms mengizinkan, approval scoped aktif dengan host list dan port range yang persis.
2. Susun execution input: host dan port range diambil persis dari approval — tidak ada penambahan, tidak ada "top ports" di luar range.
3. Jalankan `nmap_scan` dengan metode connect scan; biarkan wrapper menegakkan rate dan budget; jangan mencoba mengakali parameter yang ditolak policy.
4. Baca hasil per host: pilah open, closed, filtered; catat host yang tidak merespons sama sekali sebagai pemisahan tersendiri.
5. Bedakan filtered vs closed dengan hati-hati: timeout berulang mengindikasikan drop (filter), sedangkan RST mengindikasikan closed — jangan menyamakan keduanya.
6. Simpan hasil berkaidah di case memory, rutekan port terbuka menonjol ke attack-surface-prioritization dan technology-probing untuk identifikasi layanan lanjutan.

## Allowed Operations

- Menjalankan `nmap_scan` dengan metode connect scan (`-sT`), terbatas pada host list dan port range yang tertulis di approval aktif.
- Membaca dan menata hasil scan sebagai observation berkaidah di case memory.
- Menghentikan scan lebih awal bila hasil sudah cukup atau sinyal stop muncul.
- Merekomendasikan tindak lanjut pasif (identifikasi layanan, prioritisasi) atas port terbuka yang ditemukan.

## Approval Requirements

- Approval eksplisit WAJIB dan tidak pernah automatic: risk HIGH memetakan ke `approval_required` di policy/risk.yaml, dan capability ini dideklarasikan `requires_approval: always` di registry — tanpa approval, eksekusi ditolak.
- Approval wajib scoped penuh: capability, host, port range, metode, budget, dan expiration (ROADMAP §9); kebutuhan di luar itu berarti approval baru, bukan interpretasi longgar.
- Approval kadaluarsa menghentikan run segera; perpanjangan dibuat sebagai approval baru, bukan dilanjutkan diam-diam (ROADMAP §9, §10).
- Pencabutan approval oleh user atau program berlaku seketika; scan yang sedang berjalan dihentikan dan hasil parsial dicatat sebagai evidence.

## Forbidden Operations

- SYN scan, UDP scan, FIN/NULL/XMAS scan, OS detection, dan version detection agresif — metode di luar connect scan tidak pernah dipakai di skill ini.
- Scan terhadap host, IP, atau port di luar range yang tertulis di approval, termasuk host yang "kelihatannya satu infrastruktur".
- Scan tanpa approval aktif, dengan approval kadaluarsa, atau setelah approval dicabut.
- Retry agresif, penambahan rate, atau pembagian range untuk menghindari deteksi — penghindaran proteksi target dilarang keras.
- Menyimpulkan vulnerability dari status port; port terbuka hanyalah observation menuju analisis lain (ROADMAP §17, §26).

## Evidence Requirements

- Provenance lengkap per run: tool dan versi dari wrapper, parameter persis yang dijalankan, waktu mulai/selesai (ROADMAP §13.1).
- Hasil per host/port: keadaan (open/closed/filtered) dan dasar penentuannya (respons handshake vs timeout vs RST).
- Referensi approval yang dipakai: id, host list, port range, budget terpakai versus dialokasikan.
- Host yang tidak selesai discan (stop lebih awal, budget habis) dicatat eksplisit sebagai gap.

## False Positive Checks

- Firewall drop vs closed: host yang mem-drop semua port memunculkan timeout seragam — pola filtered menyeluruh lebih mungkin kebijakan filter, bukan keadaan tiap port.
- Load balancer atau firewall yang menjawab semua port membuat semua port tampak open — verifikasi dengan membandingkan respons antar port dan dengan konteks layanan.
- Hasil scan adalah snapshot saat itu: layanan bisa naik/turun setelah scan; jangan memperlakukan hasil lama sebagai kondisi kini.
- Rate-based tarpit dapat membuat host terlihat lebih "mati" dari kenyataan — hasil kosong bukan bukti tidak ada layanan.
- Provenance tool dicatat karena perilaku scanner bisa berubah antar versi; hasil tanpa provenance tidak dipakai (ROADMAP §13.1).

## Severity Guidance

- Skill ini tidak menetapkan severity: port terbuka bukan kerentanan; severity lahir dari analisis layanan di skill lain (mis. security-misconfiguration, injection-analysis).
- Eksposur layanan sensitif (panel admin, database) dicatat sebagai observation prioritas tinggi dan dirutekan untuk analisis, bukan dilaporkan sebagai finding port.
- Kecenderungan berbahaya yang dijaga: memperluas scan "sedikit saja" demi kelengkapan — pelanggaran approval lebih berat daripada daftar port yang kurang lengkap.

## Stop Conditions

- Approval kadaluarsa atau dicabut di tengah run → stop segera, catat hasil parsial (ROADMAP §9, §10).
- Target merespons dengan pemblokiran massal (semua koneksi dibuang setelah sebagian terpindai) atau sinyal proteksi lain → stop; lanjutkan hanya dengan keputusan user.
- Budget scan habis → stop dan rangkum cakupan yang tercapai.
- Muncul indikasi target bukan milik scope (mis. konten layanan dari pihak lain) → stop untuk host itu, tandai, konfirmasi ke user sebelum apa pun lanjut.

## Output Format

- Hasil scan per host: port, keadaan (open/closed/filtered), dasar penentuan, dan waktu.
- Provenance run: tool, versi, parameter, referensi approval, dan budget terpakai.
- Daftar gap: host/port yang tidak tercakup beserta alasannya.
- Rekomendasi tindak lanjut pasif: identifikasi layanan via technology-probing dan prioritisasi via attack-surface-prioritization.

## Related Skills

- `engagement-scoping` — sumber scope entries, program terms, dan kebutuhan approval.
- `technology-probing` — identifikasi layanan di atas port terbuka, dengan risk lebih rendah.
- `attack-surface-prioritization` — konsumen utama peta port/layanan untuk urutan pengujian.
- `false-positive-analysis` — pembedahan hasil scan yang janggal (filtered vs closed, catch-all).
- `security-misconfiguration` — analisis layanan sensitif yang terekspos.
- `http-proxy-traffic-analysis` — pembanding dari data traffic terekam saat scan tidak diperlukan.
