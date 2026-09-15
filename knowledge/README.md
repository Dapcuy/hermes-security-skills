# Knowledge Base (ROADMAP v3.0 §23, §24, §61)

Knowledge base adalah **curated reference** — BUKAN memori agent. Sejak
ROADMAP v3.0, "memory" dihapus sebagai komponen utama project (§24 Why
Skill > Memory): state kasus hidup di **evidence + jobs + approval +
events**, bukan di direktori "memori" yang menumpuk state antar
engagement. Knowledge menjawab "apa yang diketahui dan menjadi
referensi"; skill menjawab "bagaimana Hermes berpikir"; evidence
menjelaskan "apa yang benar-benar terjadi".

## Struktur direktori (§23)

```
knowledge/
├── canonical/        — reference stabil (state=trusted; promosi oleh
│                       keputusan owner)
├── research/         — hasil ingest, menunggu review (state=proposed)
├── methodology/      — curated manual: metodologi & pola reasoning
├── false-positives/  — curated manual: katalog false positive
└── reviewed/         — lolos human review (state=reviewed)
```

`research/`, `methodology/`, dan `false-positives/` masing-masing punya
README yang menjelaskan isi yang sah, siapa yang menulis, dan aturan
provenance.

## Prinsip isi — apa yang boleh masuk knowledge

```
Knowledge HANYA untuk:
  - pengetahuan reference yang sudah direview (state=reviewed/trusted)
  - pelajaran engagement yang sudah divalidasi + provenance manusia
  - katalog false positive dan pola metodologi spesifik-kasus

Knowledge BUKAN tempat:
  - state kasus        -> hidup di jobs/ + evidence + approval + events
  - metodologi umum    -> tulis sebagai SKILL.md (curated, versioned,
                          lolos linter — ROADMAP §7, §9)
  - konten target      -> hidup di evidence (knowledge firewall, §20)
```

Alasan: skill adalah sumber kebenaran metodologi yang direview dan
ter-versioning; knowledge adalah reference yang ditinjau manusia.
Mencampur state engagement yang berumur pendek ke dalamnya membuat
konteks tidak terkontrol menempel antar engagement (persis masalah
"agent memory" yang dihapus di v3.0).

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

## Lifecycle (§23)

```
captured → normalized → proposed → reviewed → trusted
     ↘ stale (last_reviewed > 90 hari, `knowledge stale`)
     ↘ archived (terminal)
```

## Perintah CLI

```
hermes-security knowledge ingest <file> --category <c> --source <s> --confidence <f>
hermes-security knowledge list [--state s] [--category c]
hermes-security knowledge search <query>
hermes-security knowledge review <id> --state reviewed
hermes-security knowledge stale
hermes-security case clean <case-id> [--force]   # case retention = jobs cleanup
```

## Knowledge firewall (§20, §23) — PENTING

Konten yang berasal dari target (response body, header, error message)
TIDAK BOLEH masuk direktori ini melalui jalur apapun:

- `knowledge ingest` MENOLAK fail-closed entry dengan
  `provenance.source: target-controlled` atau `trust: untrusted` —
  target-controlled content tidak boleh masuk knowledge base; konten
  target hidup di **evidence** (berprovenance, ber-hash).
- Entry yang membawa cap `target-controlled` ditolak walau frontmatter-nya
  memalsukan `trust: trusted` — review manusia yang sah menulis ulang
  sumbernya (diverifikasi unit test).
- Entry untrusted yang diletakkan manual tidak bisa dipromosikan ke
  `reviewed`/`trusted` oleh `knowledge review` (fail-closed).
