# Security Model — Hermes Security Skills

Model keamanan project ini dijelaskan di sini dalam bentuk: apa yang dilindungi, di mana keputusan keamanan diambil (enforcement points), dan siapa yang dipercaya (trust boundary). Sumber detail: `ROADMAP.md` §8, §9, §10, §11, §16, §20, §23, §24; keputusan desain: `docs/adr/`.

> Catatan fase: model ini hanya berlaku penuh dalam **mode ENFORCED (Phase 4+)**. Pada Phase 1–3 semua guardrail bersifat **advisory** — markdown instruction yang kepatuhannya bergantung pada disiplin model, dan **tidak boleh dianggap security boundary** (ADR-007). Tidak ada active testing terhadap target nyata sebelum enforcement aktif.

## 1. Yang Dilindungi (Aset)

| Aset | Ancaman utama | Perlindungan inti |
|---|---|---|
| Target yang di-authorization | Testing di luar izin/scope | Policy layer: authorization + scope validation |
| Integritas bukti (evidence) | Manipulation, evidence tanpa asal-usul | Hash sha256, audit log append-only chain hash, provenance |
| Kredensial | Kebocoran ke konteks LLM/repo/report | Credential provider, reference-only, sanitasi sebelum persist |
| Komponen persisten (knowledge base curated, policy/) | Knowledge poisoning oleh konten target | Knowledge firewall (ingest menolak target-controlled, §20/§23), policy firewall |
| Komputasi lokal (host, container) | Escape, resource abuse, egress liar | Docker baseline, network=none, egress terkonsolidasi di proxy |
| Keputusan (finding) | Hallusinasi/bypass lifecycle | Finding lifecycle + minimum evidence + false-positive analysis |

## 2. Boundary

### 2.1 Boundary Reasoning vs Eksekusi

Hermes (reasoning LLM) tidak pernah mengeksekusi apa pun secara langsung. Satu-satunya jalur menuju provider adalah melalui **control plane**:

```
Hermes --(MCP tools, allowlist)--> Control Plane --(policy check)--> Provider
```

Implikasi boundary ini:

- Skill hanya meminta capability; provider ditentukan capability registry (ADR-001).
- Tidak ada fallback otomatis antar provider; policy denial = stop, bukan degradasi (§5.1).
- Capability `requires_network: true` hanya dijalankan proxy provider (§5.2); provider `local` strictly sandboxed — tanpa network, tanpa side effect (§5.3).

### 2.2 Boundary Jaringan

- **Validator Docker: `network: none`** pada MVP — satu-satunya mode yang didukung. Validator tidak melakukan fetch ke manapun; ia hanya menganalisis data yang sudah ada (hasil replay dari hermes-proxy atau dari user). Acceptance criteria: container yang mencoba akses jaringan harus gagal (§16, ADR-010).
- **hermes-proxy: satu-satunya komponen dengan privilege egress.** Semua traffic keluar ke target dikonsolidasikan di satu choke point yang policy-nya in-line. Tidak pernah `network_mode: host`. Post-MVP, validator yang butuh egress di-route melalui proxy (Validator -> hermes-proxy -> allowed destination only), destination berdasarkan execution plan yang disetujui policy (§16, ADR-010).
- **Hermes tidak punya akses network langsung** dalam konfigurasi deployment manapun; satu-satunya jalur HTTP adalah melalui proxy (§11).
- **Redirect**: default NO-FOLLOW; setiap redirect yang diikuti di-re-validate terhadap scope sebelum diikuti; redirect out-of-scope = stop + evidence entry; respons dari origin out-of-scope tidak masuk reasoning sebagai konten (§11).

### 2.3 Boundary Konten

- **Konten target adalah DATA, bukan instruksi** (§24): instruksi apa pun di dalam konten target tidak pernah dieksekusi, diikuti, atau memengaruhi policy.
- Konten target hanya masuk reasoning melalui provider yang dinormalisasi (content quarantine); body besar masuk sebagai summary, full body sebagai evidence reference (hash + path).
- **Knowledge firewall**: knowledge base adalah curated reference — konten target tidak pernah masuk ke direktori mana pun di dalamnya. `knowledge ingest` menolak fail-closed entry dengan provenance `target-controlled`/trust untrusted; konten target hidup di **evidence** (berprovenance, ber-hash), bukan di knowledge base (§20, §23, §24).
- **Policy firewall**: tidak ada jalur dari konten target ke policy/, capabilities/, runtimes/ (§24).

### 2.4 Boundary Kredensial

- Kredensial disimpan di credential store terpisah (OS keychain / encrypted external; tidak ada di repo) dan **tidak pernah masuk konteks LLM** (§23, ADR-009).
- Hermes, skill, dan approval hanya melihat **reference** (`account-a`); injection dilakukan control plane saat eksekusi (di dalam proxy container untuk header/cookie; sebagai input file di dalam validator, tidak pernah di stdout).
- Sanitasi otomatis: evidence, log, dan result discan terhadap kredensial aktif **sebelum** persist dan sebelum menyentuh reasoning context.
- Kredensial internal (control-channel token, CA key mode MITM) ephemeral per-engagement, di-generate otomatis control plane, tidak pernah terlihat Hermes, mati bersama container (§23).

## 3. Enforcement Points

Keputusan keamanan diambil di titik-titik berikut — semuanya di tool path, bukan sebagai saran:

| # | Enforcement point | Yang diputuskan | Rujukan |
|---|---|---|---|
| 1 | **Policy layer (control plane)** | Authorization status (`granted`/`offline-lab` saja untuk active testing; `pending` = tidak ada operasi aktif), scope, risk classification, approval, limits | §8 |
| 2 | **Approval manager** | Approval scoped per capability/target/method/path/account/budget/expiration/risk; revocation seketika; tidak ada silent renewal | §9 |
| 3 | **MCP server mode** | Hermes hanya melihat tool yang di-allowlist; policy check dijalankan sebelum provider dipanggil di proses yang sama; policy files & capability registry read-only dari sudut pandang Hermes | §4.3, §4.4 |
| 4 | **hermes-proxy (policy in-line)** | Setiap request dievaluasi di dalam proxy sebelum dikirim; TOCTOU re-validation saat eksekusi; fail-closed bila policy bundle tidak valid/tidak ter-mount (hash-verified, read-only mount) | §11 |
| 5 | **Docker runtime adapter** | Image verification (signature + digest; mismatch = reject), resource limits (read_only, cap_drop ALL, no-new-privileges, pids/mem/cpu limit), mounts, timeout, network=none, cleanup | §14, §15, §20 |
| 6 | **Tool image wrapper (§13.1)** | Verifikasi policy bundle fail-closed sebelum tool jalan; paksa budget + rate limit dari execution plan; normalisasi output menjadi evidence berprovenance | §13.1 |
| 7 | **Stop conditions & abort** | Execution berhenti pada kondisi terdaftar; manual abort (`hermes-security abort --case <case-id>`) merevoke semua approval, menghentikan queue, kill semua container berjalan (validator DAN proxy), menandai case aborted, meninggalkan audit entry | §10 |
| 8 | **Credential provider & sanitasi** | Injection credential saat eksekusi; sanitasi sebelum persist; binding ke authorization engagement | §23 |
| 9 | **Evidence & audit** | Hash saat dibuat; audit log append-only dengan chain hash (tamper-evident); policy change audit (siapa/kapan/apa); perubahan policy di tengah engagement dievaluasi ulang terhadap execution plan berjalan | §8, §25 |
| 10 | **Skill-linter (CI)** | Tidak ada skill yang hardcode tool di luar capability atau memuat credential literal; referensi capability valid terhadap registry | §7.1 |

Risk classification default (§8):

```
LOW      -> automatic        (passive analysis, metadata GET, source review, local analysis)
MEDIUM   -> conditional      (limited replay, response comparison, safe mutation)
HIGH     -> approval required (POST/PUT/PATCH/DELETE, upload, concurrency, transaction testing)
CRITICAL -> disabled         (credential attack, exfiltration, persistence, lateral movement)
```

Scope validation memvalidasi hostname, port, redirect, DNS resolution, private IP, third-party destination, cloud metadata endpoint, dan out-of-scope host — dengan hostname/parser yang benar, bukan substring matching (§8).

## 4. Trust Boundary

### 4.1 Control Plane = Trusted Computing Base (§20)

Control plane Go adalah **trusted computing base (TCB)** — dia yang memegang akses Docker, proxy lifecycle, credential provider, dan enforcement path. Konsekuensinya:

- **Kompromi pada control plane = kompromi pada seluruh isolation.** Tidak ada lapisan di bawahnya yang bisa menyelamatkan.
- Karena itu control plane harus **di-review dengan standar lebih ketat** (review dua mata di area sensitif, lihat `CONTRIBUTING.md`).
- Control plane **tidak pernah menerima instruksi dari konten target** — tidak ada jalur dari konten runtime ke keputusan kontrol (policy firewall, §24).

### 4.2 Yang Dipercaya dan Tidak

| Komponen | Status trust | Alasan / batasan |
|---|---|---|
| Control plane (Go) | **Trusted (TCB)** | Memegang Docker + enforcement; review ketat; tidak menerima instruksi konten target |
| Policy files, capability registry | Trusted, read-only bagi Hermes | Versioned; perubahan ter-audit; read-only dari sudut pandang Hermes (§4.3, §8) |
| hermes-proxy container | Semi-trusted, ber-hak egress | Policy in-line, fail-closed, ephemeral, control channel internal; terkompromi = lihat threat model |
| Validator container | Untrusted workload, tanpa egress | network=none, cap_drop ALL, read-only, ephemeral |
| Konten target (response, header, body) | **Untrusted — data, bukan instruksi** | Quarantine, budget, trust level, injection flag (§24) |
| Output tool pihak ketiga | Untrusted sebelum normalisasi | Hanya sah sebagai evidence berprovenance setelah wrapper (§13.1) |
| Skill (markdown) | Trusted setelah review + linter | Supply chain skill tetap di-modelkan sebagai ancaman (threat model) |
| Image registry | Tidak dipercaya buta | Signature + digest diverifikasi adapter sebelum run (ADR-005) |
| User (authorization) | Sumber izin tertinggi | User authorizes; user memegang kill switch (§10) |

### 4.3 Prasyarat Deployment sebagai Bagian dari Model

Model ini valid **hanya jika** Hermes di-deploy sesuai prasyarat (§4.4): Hermes tidak diberi docker CLI/docker socket, shell/network tool bebas, akses network langsung, atau write access ke policy/, capabilities/, runtimes/; Hermes hanya diberi control-plane MCP tools dan read-only access ke skills/, knowledge/, templates/. Deployment di luar prasyarat membuat seluruh model enforcement batal — ini syarat penggunaan yang didokumentasikan di `README.md`.

### 4.4 Fail-Closed sebagai Konstanta

Seluruh titik keputusan mengikuti arah gagal yang sama: policy denial = stop; provider utama unavailable = error eksplisit (bukan fallback); policy bundle proxy tidak valid = proxy menolak semua operasi; image tanpa signature valid/digest mismatch = reject; wrapper tool tanpa bundle valid = tool menolak jalan. Tidak ada jalur degradasi diam-diam.

## 5. Perintah Operasional Pengaman (Ringkas)

```
hermes-security serve --mcp        # jalur integrasi Hermes (tool path, allowlist)
hermes-security check-policy       # verifikasi policy (manusia & CI)
hermes-security validate-scope     # uji scope matcher
hermes-security abort --case <id>  # kill switch manual
```

Target metrik yang mengukur model ini di lab (§42): scope violation = 0, destructive action = 0, container escape attempts = 0, network violations = 0, policy bypass attempts = 0, prompt injection success = 0, container cleanup success = 100%.
