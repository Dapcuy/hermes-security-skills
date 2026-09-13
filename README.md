# Hermes Security Skills

Modular security reasoning and validation skill pack untuk Hermes.

Fokus project ini **bukan** autonomous pentest framework. Fokusnya adalah membuat Hermes lebih mampu:

- Memahami metodologi bug bounty dan pentesting yang authorized.
- Memilih skill berdasarkan konteks target.
- Membuat dan mengelola security hypothesis.
- Memilih capability dan provider yang relevan.
- Menggunakan **hermes-proxy** untuk analisis HTTP.
- Menggunakan Docker untuk controlled dan reproducible validation.
- Mengumpulkan dan menilai evidence.
- Mengurangi false positive.
- Menulis security report yang berkualitas.
- Membantu riset kandidat vulnerability yang potentially novel.

## Prinsip Utama

```
Skills teach.
Hermes reasons.
Policy decides — and enforces, not merely advises.
Proxy observes and interacts.
Docker validates.
Evidence proves.
Memory preserves knowledge.
Credentials never touch the reasoning context.
User authorizes.
```

Dua prinsip ini bersifat mutlak dan menjadi dasar seluruh desain:

1. **Skill tidak mengetahui tool.** Skill hanya meminta *capability* abstrak (mis. `request_replay`), tidak pernah hardcode tool (`mitmproxy`, `curl`, Docker). Provider ditentukan oleh capability registry.
2. **Policy decides — and enforces.** Policy dieksekusi di tool path, bukan diberikan sebagai saran. Satu-satunya jalur ke provider adalah melalui control plane.

## Quickstart

Prasyarat: **Go 1.22+** (stdlib only), **Python 3** (skill-linter dan target uji lokal), **Docker** (opsional — validator image dan offline lab), **make** (opsional — di Windows sering tidak terpasang; pakai perintah langsung di bawah).

```bash
# 1. Build semua package Go (control plane, hermes-proxy, validator)
go build ./...

# 2. Jalankan semua test Go
go test ./...

# 3. Validasi skills/ dengan skill-linter
python tools/skill-linter/lint.py skills/

# 4. Build satu validator image (build context = root repo)
docker build -f runtimes/docker/images/http-validator/Dockerfile \
  -t hermes/http-validator:dev .
```

Empat perintah di atas setara dengan target Makefile `go-build`, `go-test`,
`lint-skills`, dan `docker-build`. Target lain: `go-vet` = `go vet ./...`,
`lab-up`/`lab-down` = `docker compose -f labs/docker-compose.yml up -d|down`
(hanya untuk offline lab, §8/§42).

Coba hermes-proxy (replay engine) end-to-end — satu perintah, bisa
dijalankan ulang, otomatis shutdown + cleanup:

```bash
bash scripts/demo-e2e.sh                                  # Git Bash / Linux / macOS
powershell -ExecutionPolicy Bypass -File scripts\demo-e2e.ps1   # PowerShell
```

Langkah manual Mode 1 dan Mode 2 (TLS MITM) ada di
[`cmd/hermes-proxy/README.md`](cmd/hermes-proxy/README.md).

## Ringkasan Arsitektur

```
                         HERMES
                            |
                     +------+------+
                     | Skill Layer |
                     +------+------+
                            |
                     Capability Request
                            |
                     +------+------+
                     | Policy Layer |   <-- enforcement point,
                     +------+------+       bukan saran
                            |
                     Approved Execution Plan
                            |
              +-------------+-------------+
              |                           |
              v                           v
       PROXY PROVIDER              DOCKER PROVIDER
              |                           |
      hermes-proxy Container    Docker Runtime
      (ephemeral, egress only)        |
              |                  Validator Image
              |                        |
              |                        v
              |                 Structured Evidence
              |                           |
              +-------------+-------------+
                            |
                            v
                    Evidence Layer
                            |
                            v
                       Hermes Reasoning
                            |
                            v
                         Finding
```

Pembagian tanggung jawab:

```
Skill:
  methodology dan reasoning guidance

Hermes:
  hypothesis, routing, decision making

Policy:
  authorization, scope, risk, approval, limits
  (dieksekusi di tool path, bukan sebagai saran)

Capability:
  abstract operation yang diminta skill

Proxy (hermes-proxy):
  HTTP replay, mutation, comparison, traffic
  observation — ephemeral container, satu-satunya
  komponen dengan privilege egress

Docker:
  deterministic/reproducible validator execution

Evidence:
  structured proof dan provenance

Credential Provider:
  penyimpanan dan injeksi kredensial tanpa
  melalui konteks reasoning

Memory:
  case knowledge dan reviewed experience
```

Konsekuensi penting dari arsitektur ini:

- **Validator Docker berjalan dengan `network: none`** pada MVP — validator tidak melakukan fetch ke manapun dan hanya menganalisis data yang sudah ada.
- **`hermes-proxy` adalah satu-satunya komponen dengan privilege egress.** Semua traffic keluar ke target dikonsolidasikan di satu choke point yang policy-nya in-line (dievaluasi di dalam proxy container, dengan TOCTOU re-validation saat eksekusi).
- **Kredensial tidak pernah masuk konteks LLM.** Skill dan approval hanya merujuk *credential reference*; injection dilakukan control plane saat eksekusi.
- **Konten target adalah data, bukan instruksi.** Prompt injection dan content trust ditangani sebagai first-class concern (structural separation, content quarantine, knowledge firewall, policy firewall).
- Versi arsitektur final (dengan supporting components di luar reasoning path) dijelaskan di `ROADMAP.md` §47.

## Batasan Project

### In-Scope

- Security methodology.
- Bug bounty reasoning.
- Web dan API analysis.
- HTTP traffic analysis.
- Controlled validation.
- Source review guidance.
- Evidence handling.
- Finding triage.
- Report generation.
- Knowledge dan memory management.

### Non-Goals

Project ini **tidak ditujukan untuk**:

- Autonomous unrestricted scanning.
- Credential stuffing.
- Password cracking terhadap target nyata.
- Data exfiltration.
- Persistence.
- Lateral movement.
- Destructive testing.
- Automatic public disclosure.
- Automatic vulnerability submission tanpa human approval.
- Menganggap payload berhasil sebagai vulnerability valid.

## Deployment Prerequisites Hermes — SYARAT KEAMANAN (WAJIB DIBACA)

Enforcement model pada project ini hanya valid jika Hermes di-deploy dengan benar. Jika Hermes di-deploy dengan akses penuh, **seluruh model enforcement batal**. Prasyarat deployment:

```
Hermes TIDAK diberi:
  - docker CLI / docker socket
  - shell atau network tool bebas (curl, ncat, dsb.)
  - akses network langsung / koneksi langsung ke
    proxy container
  - write access ke policy/, capabilities/, runtimes/

Hermes HANYA diberi:
  - control-plane MCP tools (capability interface)
  - read-only access ke skills/, knowledge/, templates/
```

Catatan tambahan yang menyertai prasyarat ini:

- Control plane di-expose ke Hermes sebagai **MCP server** (`hermes-security serve --mcp`). Hermes hanya melihat MCP tool yang sudah melalui allowlist.
- Setiap tool yang berisiko mengeksekusi policy check **sebelum** provider dipanggil — di dalam proses yang sama. Tidak ada operasi yang "meminta Hermes untuk rajin menjalankan check-policy" — check berjalan karena tidak ada jalur lain.
- Policy files dan capability registry bersifat read-only dari sudut pandang Hermes.
- Perbedakan selalu dua mode guardrail: **ADVISORY** (Phase 1–3, markdown instruction, kepatuhan bergantung disiplin model, **bukan security boundary** — hanya untuk development/reasoning dry-run/lab lokal) dan **ENFORCED** (Phase 4+, dieksekusi di tool path, Hermes secara teknis tidak bisa mem-bypass — barulah itu security boundary). Tidak ada active testing terhadap target nyata sebelum enforcement aktif.

Ini adalah syarat penggunaan, bukan rekomendasi opsional.

## Struktur Repository

```
hermes-security-skills/
├── README.md            dokumen ini
├── SKILL.md             entry skill pengantar (cara memilih skill)
├── RULES.md             aturan mutlak operasi
├── ROUTING.md           tabel routing gejala -> skill
├── CHANGELOG.md         riwayat versi
├── CONTRIBUTING.md      panduan kontribusi
├── LICENSE              MIT
├── docs/
│   ├── adr/             Architecture Decision Records (ADR-001..010)
│   ├── security-model.md
│   └── threat-model.md
├── skills/              skill pack per kategori (core, recon, http, web, api, ...)
├── capabilities/        capability registry + schemas
├── policy/              authorization, scope, risk, approval, limits
├── runtimes/            docker/, proxy/, local/ (runtime adapters + images)
├── validators/          validator logic per domain
├── schemas/             JSON Schema (execution-plan, validation-task, evidence, ...)
├── tools/               skill-linter dan tooling lain
├── memory/              case memory (global/ + cases/)
├── knowledge/           canonical, methodology, false-positives, ...
├── references/          referensi eksternal
├── templates/           template output (finding, report)
└── tests/               pengujian
```

Catatan: credential store **tidak ada di repo** — lokasinya di luar (OS keychain / encrypted external store). Detail credential management ada di `ROADMAP.md` §23 dan `docs/security-model.md`.

## Dokumentasi Utama

| Dokumen | Isi |
|---|---|
| `ROADMAP.md` | Spesifikasi lengkap: visi, arsitektur, fase, exit criteria |
| `SKILL.md` | Entry point untuk memilih skill |
| `RULES.md` | Aturan mutlak (authorization, scope, stop conditions, abort) |
| `ROUTING.md` | Pemetaan gejala/konteks ke skill yang relevan |
| `docs/security-model.md` | Boundary, enforcement points, trust boundary |
| `docs/threat-model.md` | Threat utama dan mitigasinya |
| `docs/adr/` | Architecture Decision Records |

## Lisensi

MIT — lihat `LICENSE`.
