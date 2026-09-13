# Knowledge Base (ROADMAP §27, §41)

Struktur direktori:

```
knowledge/
├── canonical/   — knowledge ter-review penuh (state=trusted)
├── proposed/    — entry hasil ingestion, menunggu review
│                  (state=captured|normalized|proposed)
└── reviewed/    — entry yang sudah lolos human review (state=reviewed)
```

## Prinsip owner — apa yang boleh masuk knowledge

```
Knowledge HANYA untuk:
  - pelajaran spesifik-kasus yang sudah direview (state=reviewed)
  - keputusan yang direview beserta rationale-nya

Knowledge BUKAN tempat generalisasi METODOLOGI security.
Bila pelajaran ternyata generalisasi menjadi metodologi (teknik,
workflow, kriteria yang berlaku lintas kasus), tulis sebagai SKILL.md
baru atau perbaiki skill yang ada - curated, versioned, lolos linter
(ROADMAP §7, §7.1) - bukan sebagai entry knowledge.
```

Prinsip yang sama berlaku sebaliknya untuk memory: memory hanya menyimpan
state kasus, keputusan, evidence reference, dan approval (lihat
`memory/README.md`). Contoh penerapan: `lesson-sqli-boolean-differential`
adalah pelajaran spesifik-kasus engagement Juice Shop - teknik boolean
differential-nya sudah ter-cover di `skills/web/injection-validation`,
sehingga entry direlokasi ke `memory/cases/juice-demo/`, bukan dipertahankan
sebagai entry knowledge.

## Format entry

Markdown + frontmatter YAML subset (`internal/yamlmini`):

```markdown
---
id: xss-reflected-note
title: Reflected XSS in search parameter
category: xss-analysis
source: manual-research
confidence: 0.8
state: proposed
last_reviewed: 2026-09-13T00:00:00Z
provenance:
  source: manual
  trust: trusted
---

Body markdown (definisi, detection signal, false positive, referensi, ...).
```

## Lifecycle (§27)

```
captured → normalized → proposed → reviewed → trusted
     ↘ stale (last_reviewed > 90 hari, `knowledge stale`)
     ↘ archived (terminal)
```

## Perintah CLI

```
hermes-security knowledge ingest <file> --category <c> --source <s> --confidence <f>
hermes-security knowledge list [--state s]
hermes-security knowledge search <query>
hermes-security knowledge review <id> --state reviewed
hermes-security knowledge stale
hermes-security case archive --case <id>
```

## Knowledge firewall (§24) — PENTING

Konten yang berasal dari target (response body, header, error message)
TIDAK BOLEH masuk direktori ini melalui jalur apapun. Konten target hanya
boleh menjadi entry state=captured di `memory/cases/<caseID>/` dengan
provenance `trust: untrusted` — via `memory.Store.IngestFromTarget`.
Promosi entry untrusted ke reviewed/trusted ditolak fail-closed oleh
control plane (diverifikasi unit test).
