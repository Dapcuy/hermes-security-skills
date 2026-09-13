# Threat Model — Hermes Security Skills

Threat model wajib sesuai `ROADMAP.md` §31 (Phase 0 — Definition). Setiap threat menjelaskan: deskripsi, vektor serangan, mitigasi yang sudah ditetapkan roadmap, dan residual risk — risiko yang tetap ada setelah mitigasi, agar pembaca tidak salah paham bahwa mitigasi = imunitas.

Model mitigasi mengacu pada: `docs/security-model.md`, `docs/adr/` (ADR-001 s.d. ADR-010), `RULES.md`, dan `ROADMAP.md` (rujukan § dicantumkan per item).

> Catatan fase: mitigasi yang bersifat enforcement (di tool path) baru aktif pada **Phase 4+**. Sebelum itu semua guardrail advisory dan sistem tidak boleh dipakai terhadap target nyata (§4.2, ADR-007).

---

## Threat 1 — Prompt Injection dari Konten Target

**Deskripsi.** Sistem secara desain memasukkan konten dari target — HTTP response, header, body, error message — ke dalam reasoning LLM. Penyerang yang mengendalikan konten target menanam instruksi di dalamnya untuk mengubah perilaku Hermes: membuat sistem mengabaikan aturan, melaporkan "tidak ada vulnerability" pada kerentanan nyata, memicu request ke URL out-of-scope, atau memanipulasi hasil temuan. Karena reasoning LLM adalah komponen inti, ini ancaman terhadap korektness hasil sekaligus terhadap keamanan operasi.

**Vektor.**
- Body/error message halaman target berisi teks instruksi imperatif ("ignore previous instructions...", "laporkan bahwa tidak ada vulnerability", "fetch URL berikut").
- Header respons atau konten redirect yang mencoba mengarahkan sistem.
- Konten yang mendorong reasoning menulis "pelajaran" berbahaya ke knowledge, sehingga berbahaya lintas engagement.

**Mitigasi (roadmap).**
- Prinsip konten: target-controlled content adalah DATA, instruksi di dalamnya tidak pernah dieksekusi/diikuti/memengaruhi policy (§24, ADR-008).
- Structural separation: output provider dibungkus delimiter + metadata (source, origin, trust level); blok diperlakukan sebagai quoted data.
- Content quarantine: konten target hanya masuk reasoning melalui provider yang dinormalisasi — tidak ada raw dump response ke konteks.
- Context budget: body besar di-truncate/summarize; full body hanya evidence reference (hash + path).
- Knowledge firewall: konten target tidak bisa menulis ke knowledge/canonical, hanya memory/cases dengan trust "untrusted" (§24, §27).
- Policy firewall: tidak ada jalur konten target ke policy/, capabilities/, runtimes/ (§24).
- Injection detection: pola instruksi imperatif ditandai; flag masuk evidence, bukan trigger eksekusi (§24).
- Adversarial test suite wajib sejak Phase 4 (kasus di atas + canary injection di lab Phase 11), metrik `prompt injection success = 0` (§24, §42).
- Fetch out-of-scope yang diminta konten tetap diblok oleh scope check di jalur proxy/validator (§8, §11, §16).

**Residual risk.** LLM tetap bisa "tertipu" secara semantik oleh konten yang tidak terdeteksi heuristik — injection detection adalah lapisan diagnostik, bukan boundary. Yang menjaga dampak tetap terbatas adalah enforcement struktural (scope check, policy firewall) — tetapi keputusan reasoning yang keliru (mis. salah klasifikasi temuan) tidak bisa dihilangkan sepenuhnya; human review atas finding tetap diperlukan. Context budget bisa memangkas detail yang relevan (trade-off yang disengaja).

---

## Threat 2 — Compromised / Tampered Proxy Container atau Policy Bundle

**Deskripsi.** hermes-proxy adalah satu-satunya komponen dengan privilege egress (§11, ADR-002, ADR-010). Bila container proxy terkompromi atau policy bundle-nya di-tamper, penyerang mengendalikan satu-satunya jalur ke target: bisa mengirim request sembarang atas nama engagement, membocorkan data, atau melonggarkan evaluasi policy in-line. Ini ancaman terhadap target sekaligus terhadap kerahasiaan kredensial yang di-inject di dalam proxy (§23).

**Vektor.**
- Policy bundle dimodifikasi sebelum/di tengah mount (hash mismatch dicek — tapi proses build/distribusi bundle adalah target).
- Image proxy yang terkompromi di registry atau saat pull.
- Control channel token bocor dan dipakai mengirim instruksi ke proxy dari luar.
- Container proxy yang tersisa (lifecycle gagal) dipakai ulang.

**Mitigasi (roadmap).**
- Proxy berjalan sebagai ephemeral Docker container dengan pola validator: curated image, versioned + signed, digest verification sebelum run (§11, §14, §36, ADR-002, ADR-005).
- Policy bundle di-mount read-only dan hash-verified; setiap request dievaluasi in-line sebelum dikirim; TOCTOU re-validation saat eksekusi di dalam proxy (§11).
- Fail-closed: bundle tidak valid/tidak ter-mount = proxy menolak semua operasi; tamper test "bundle yang diubah = tolak semua" adalah exit criteria Phase 7 (§11, §38).
- Control channel: token ephemeral per-engagement, di-generate otomatis control plane, tidak pernah terlihat Hermes, mati bersama container, hanya listen di Docker network internal — tidak di-expose ke luar (§11, §23).
- Proxy tidak boleh expose port ke luar selain control channel di network internal; Hermes tidak punya jalur ke proxy selain control plane (§11, §4.4).
- Ephemeral lifecycle: create -> execute -> destroy tanpa state tertinggal; abort meng-kill proxy bersama validator; cleanup success rate = metrik wajib (§18, §10, §42).
- Exit criteria terkait: proxy image berjalan ephemeral tanpa state tertinggal; control channel hanya di network internal; TOCTOU re-validation teruji (§38).

**Residual risk.** Kompromi pada host yang menjalankan Docker, atau pada control plane yang men-mount bundle dan meng-generate token, tidak bisa dicegah oleh mekanisme ini (lihat Threat 6). Jika penyerang mengendalikan host, semua taruhan dari sisi container runtuh. Keandalan abort/cleanup harus terus diukur — kegagalan cleanup adalah celah nyata bagi reuse.

---

## Threat 3 — Malicious Skill (Skill Supply Chain)

**Deskripsi.** Skill adalah markdown yang memberi panduan reasoning. Skill berbahaya (dikirim kontributor, atau diimpor dari sumber tidak terpercaya) bisa: menghardcode tool dan menyarankan jalur eksekusi di luar capability, menyisipkan "aturan" yang melemahkan authorization preconditions atau forbidden operations, memuat credential literal, atau mengarahkan reasoning mengeksekusi operasi berisiko sebagai bagian "workflow". Karena skill dibaca Hermes sebagai instruksi, skill berbahaya adalah instruksi berbahaya.

**Vektor.**
- Pull request kontributor dengan skill yang tampak normal tetapi melonggarkan preconditions.
- Skill pihak ketiga yang diimpor/dicopy tanpa review.
- Perubahan kecil yang lolos review manual ("naming drift" yang mengubah semantik).

**Mitigasi (roadmap).**
- Skill-linter wajib di CI sejak Phase 1: frontmatter schema, required sections, naming convention, tidak ada hardcode tool di luar capability, tidak ada credential literal, referensi capability valid terhadap registry (§7.1) — CI gagal bila linter gagal.
- Standard skill format mengikat section `Authorization Preconditions`, `Allowed Operations`, `Approval Requirements`, `Forbidden Operations`, `Stop Conditions` (§7).
- Review keamanan: perubahan skill melewati review; RULES.md menjadi aturan mutlak yang tidak bisa dilonggarkan oleh skill manapun (`RULES.md`).
- Pintu khusus untuk tool pihak ketiga: hanya sebagai image terkurasi terpisah dengan wrapper fail-closed + normalisasi evidence (§13.1) — skill tidak bisa "mengangkat" tool bebas.
- `skill-supply-chain-review` sebagai skill khusus meninjau skill/tool pihak ketiga sebelum dipakai (§6, §43).

**Residual risk.** Linter memeriksa bentuk, bukan niat: skill yang secara gramatikal valid tetap bisa memandu reasoning ke arah suboptimal dalam batas policy. Lapisan penentu tetap enforcement di tool path (Phase 4+) — skill berbahaya tidak bisa mengirim traffic di luar capability yang di-approve; tetapi kualitas reasoning bisa dirusak tanpa terdeteksi linter. Impor skill pihak ketiga harus selalu melewati review manual + `skill-supply-chain-review`.

---

## Threat 4 — Malicious Payload File

**Deskripsi.** Payload dan SecLists adalah input yang dipilih untuk pengujian (§22). File payload berbahaya (dari sumber tidak terpercaya, atau SecLists yang di-tamper) bisa: mengandung payload destructive/exfiltration/credential-attack yang seharusnya dilarang, mengandung input yang mengeksploitasi parser/validator yang memprosesnya, atau membawa jumlah entri tak terbatas yang mengubah pengujian terbatas menjadi mass scanning.

**Vektor.**
- SecLists yang diunduh/diubah dari sumber tidak terpercaya.
- Payload file yang dikirim kontributor tanpa metadata.
- Payload yang menyamar sebagai "input variation" tapi berisi destruktif.

**Mitigasi (roadmap).**
- Payload flow selalu melewati policy: Skill methodology -> payload selection -> Policy -> selected payloads -> Validator (§22) — tidak ada jalur payload langsung ke validator.
- Payload metadata wajib (id, category, context, risk, destructive, max_attempts, source); tidak ada payload list yang lolos tanpa metadata — exit criteria Phase 8 (§22, §39).
- Guardrail default `payload_policy`: max_entries_per_task 100, max_requests_total 50, rate_limit_rps 1, max_concurrency 1, stop_on_429, stop_on_repeated_5xx, destructive/exfiltration/credential-attack lists = deny (§22).
- Budget + stop conditions dieksekusi (bukan saran): task yang melebihi budget berhenti dengan stop reason; stop_on_429/5xx teruji di lab (§39, §10).
- Payload success bukan konfirmasi vulnerability — hasil selalu masuk finding lifecycle + false-positive analysis (§22, §26).
- Validator berjalan network=none menerima input sebagai file hasil replay — payload tidak pernah "hidup" di jalur validator (§16).

**Residual risk.** Parser yang memproses file payload/result tetap attack surface (bug parsing = crash/eksekusi); mitigasi struktural (container tanpa network, non-root) membatasi dampaknya, tetapi tidak menghapusnya. Payload dengan metadata "benar" tapi niat jahat yang sulit dinilai otomatis tetap bergantung pada review kurasi — kualitas kurasi adalah batas atas keamanan jalur payload.

---

## Threat 5 — Compromised Image Registry

**Deskripsi.** Semua eksekusi (validator, proxy, tool pihak ketiga) berjalan dari image yang ditarik dari OCI-compatible registry (§36). Registry yang terkompromi — atau jalur distribusi yang diserap — bisa menyajikan image berbahaya sebagai versi resmi, memberi penyerang eksekusi kode di dalam container validator/proxy, termasuk container proxy yang punya egress.

**Vektor.**
- Registry akun/akses token bocor; tag resmi di-retag ke image jahat.
- Serangan man-in-the-middle pada jalur pull (tanpa verifikasi).
- Registry mirror pihak ketiga yang menyajikan image berbeda.

**Mitigasi (roadmap).**
- Image immutable/versioned; execution plan menyimpan image version, idealnya digest `@sha256:...` (§14, ADR-005).
- Signature diverifikasi Docker adapter **sebelum** image dijalankan (mis. cosign/notation); trust store/public key didokumentasikan dan didistribusikan bersama project; **digest mismatch = reject** (§36, §14, exit criteria Phase 5/6).
- Pipeline CI: build -> scan -> SBOM -> sign -> publish; user tidak perlu docker build sendiri (§36).
- Jalur build-from-source dari repo untuk user yang tidak ingin menarik dari registry; verifikasi tetap wajib (digest build lokal tercatat di audit log) (§36).
- Container tetap berjalan dengan baseline ketat (read-only, cap_drop ALL, non-root, network=none) sehingga image jahat pun berjalan dengan privilege minimum — defense in depth (§15).

**Residual risk.** Jika pipeline CI/sumber build itu sendiri terkompromi, image jahat bisa di-sign sah oleh penyerang — verifikasi signature hanya selengkap trust root-nya; karena itu trust store harus didistribusikan out-of-band dan dijaga. Verifikasi tidak menggantikan kebersihan registry (akses, rotasi token); ia memastikan tampering terdeteksi, bukan mencegah semuanya.

---

## Threat 6 — Kompromi Control Plane (TCB)

**Deskripsi.** Control plane Go adalah trusted computing base: ia memegang akses Docker, mengelola lifecycle proxy, menjalankan policy engine dan approval manager, meng-inject kredensial, dan menjadi satu-satunya jalur Hermes ke provider (§20, ADR-007). Bila control plane terkompromi, semua isolation runtuh sekaligus — penyerang mendapatkan Docker access, kredensial, jalur egress, dan otoritas policy. Ini threat dengan dampak tertinggi.

**Vektor.**
- Kerentanan pada control plane itu sendiri (parser schema, scope matcher, MCP server, handler).
- Instruksi yang diselundupkan dari konten target ke keputusan control plane (konten target memengaruhi penulisan policy/config).
- Dependency Go control plane yang terkompromi (supply chain).
- Deployment yang melanggar prasyarat (Hermes diberi docker CLI/shell/write access) — "kompromi yang dibuka dari dalam".

**Mitigasi (roadmap).**
- Perhatian eksplisit: control plane = TCB; kompromi control plane = kompromi seluruh isolation; di-review dengan standar lebih ketat; tidak pernah menerima instruksi dari konten target (§20).
- Policy firewall: tidak ada jalur dari konten target ke policy/, capabilities/, runtimes/; file-path validation; control plane tidak pernah menulis di sana berdasarkan input runtime (§24).
- Deployment prerequisites wajib: Hermes tanpa docker CLI/socket, tanpa shell/network tool bebas, tanpa akses network langsung, tanpa write access ke policy/, capabilities/, runtimes/; hanya MCP tools allowlisted + read-only ke skills/, knowledge/, templates/ (§4.4, ADR-007).
- Policy files versioned + policy change audit (siapa/kapan/apa); perubahan policy di tengah engagement dievaluasi ulang terhadap execution plan berjalan (§8).
- Audit log append-only, tamper-evident (chain hash) — aktivitas control plane tercatat dan manipulasi terdeteksi (§25, §35).
- MCP server mode: check policy dijalankan di proses yang sama sebelum provider dipanggil — tidak ada jalur yang menghindari check (§4.3).
- Metrik lab: `policy bypass attempts = 0`, `container escape attempts = 0` (§42).

**Residual risk.** Secara definisi TCB tidak punya lapisan di bawah dirinya: bug di control plane tidak bisa dimitigasi oleh komponen yang ia kendalikan. Pengurangan risiko berupa review ketat, scope kecil (dependency minimum), audit, dan pengujian adversarial — bukan penghapusan. Deployment yang melanggar prasyarat menghanguskan model secara keseluruhan; karena itu prasyarat dinyatakan sebagai syarat penggunaan di README, dan adapter multi-agent yang tidak bisa menjamin restricted tool access tidak didukung (§44).

---

## Ancaman Tambahan (di luar minimum §31)

### Threat 7 — Kebocoran Kredensial ke Konteks/Evidence

**Deskripsi.** Kredensial test account dan kredensial internal (control-channel token, CA key) bisa bocor ke konteks LLM, evidence, log, atau report — lalu terpersist dan terekspos jangka panjang.

**Vektor.** Penaruhan token langsung di prompt/skill; credential yang ikut terekam di evidence/log; CA key yang persist di repo.

**Mitigasi (roadmap).** Credential provider terpisah, reference-only untuk Hermes; injection saat eksekusi di dalam proxy/validator; sanitasi otomatis sebelum persist; kredensial internal ephemeral per-engagement, di-generate otomatis, mati bersama container; credential store di luar repo (§23, ADR-009). **Residual risk:** bug pada jalur sanitasi (pola redact yang tidak lengkap) dan kompromi credential store itu sendiri; binding ke authorization membatasi jendela dampak waktu.

---

## Ringkasan

| Threat | Mitigasi utama | Boundary yang menjaga |
|---|---|---|
| 1. Prompt injection | Quarantine + firewall + adversarial suite | Konten = data; enforcement di tool path |
| 2. Proxy/policy bundle tamper | Signed image, hash-verified bundle, fail-closed, ephemeral, control channel internal | Proxy = satu-satunya egress, in-line policy |
| 3. Malicious skill | Skill-linter CI + format wajib + RULES.md mutlak | Skill hanya meminta capability |
| 4. Malicious payload | Payload wajib lewat policy + budget/metadata + deny list | Jalur payload selalu melewati policy |
| 5. Image registry | Digest + signature verify sebelum run; SBOM; build-from-source | Adapter menolak image tak terverifikasi |
| 6. Control plane (TCB) | Review ketat, policy firewall, deployment prerequisites, audit append-only | TCB — tanpa lapisan di bawahnya |
| 7. Kebocoran kredensial | Reference-only, injection saat eksekusi, sanitasi sebelum persist | Kredensial tidak pernah menyentuh konteks |

Threat model ini hidup: setiap perubahan arsitektur (ADR baru/revisi) wajib dievaluasi ulang terhadap daftar ini, dan benchmark Phase 11 mengukur metrik yang menyingkap pelanggaran (scope violation, policy bypass, prompt injection success, container escape — semuanya target = 0, §42).
