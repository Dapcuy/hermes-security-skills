# Policy Defaults — Hermes Security Skills

Direktori ini berisi default policy yang menjadi security boundary sebelum
capability dieksekusi (ROADMAP §8). Policy bukan saran — policy decides, and
enforces (ROADMAP §1, §4.2).

## Status file: READ-ONLY dari sudut pandang Hermes

Seluruh file di direktori ini **read-only dari sudut pandang Hermes**
(ROADMAP §4.3, §4.4):

```
Hermes TIDAK diberi:
  - write access ke policy/, capabilities/, runtimes/

Hermes HANYA diberi:
  - control-plane MCP tools (capability interface)
  - read-only access ke skills/, knowledge/, templates/
```

Konsekuensinya:

- Hermes tidak dapat mengubah, menimpa, atau menambah policy.
- Tidak ada jalur dari konten target ke `policy/` (Policy firewall,
  ROADMAP §24): file-path validation + control plane tidak pernah menulis
  di direktori ini berdasarkan input runtime.
- Perubahan policy hanya dilakukan oleh pengelola project (manusia) melalui
  commit/PR — bukan oleh agent atau konten yang berasal dari target.

## Perubahan policy ter-audit (Policy Integrity, ROADMAP §8)

- Policy files bersifat versioned dan perubahannya tercatat di audit log
  (siapa / kapan / apa) — lihat `schemas/audit-log.schema.json`,
  action `policy.changed`.
- Policy tidak dapat diubah oleh konten yang berasal dari target (ROADMAP §25).
- Perubahan policy di tengah engagement otomatis dievaluasi ulang terhadap
  execution plan yang berjalan; jika hasilnya deny, eksekusi berhenti
  (stop condition: "policy berubah menjadi deny", ROADMAP §10).

## Fail-closed

Semua keputusan policy bersifat fail-closed (ROADMAP §5.1): policy tidak
terbaca, tidak valid, atau tidak lengkap = operasi DITOLAK dengan error
eksplisit — bukan dijalankan dengan default longgar, bukan fallback.

## Isi direktori

```
policy/
├── README.md                 # file ini
├── risk.yaml                 # risk class (LOW/MEDIUM/HIGH/CRITICAL) +
│                             # default action per class (ROADMAP §8)
├── limits.yaml               # payload_policy: budget, rate limit,
│                             # stop conditions, payload yang dilarang
│                             # (ROADMAP §22)
├── approval/
│   └── template.yaml         # contoh scoped approval + aturan
│                             # revocation/renewal (ROADMAP §9)
└── scope/
    └── defaults.yaml         # scope validation defaults: hostname
                              # exact-match, port, redirect, DNS,
                              # private IP, cloud metadata,
                              # out-of-scope host (ROADMAP §8)
```

Catatan: `policy/authorization/` (status authorization engagement:
pending / granted / offline-lab, ROADMAP §8) diisi per-engagement dan tidak
menyimpan default di repo.
