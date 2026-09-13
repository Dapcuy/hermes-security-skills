# Memory (ROADMAP §27, §25)

```
memory/
├── global/   — memori lintas-engagement (MVP: kosong)
└── cases/    — case memory per engagement: memory/cases/<caseID>/
```

## Case memory

Setiap engagement punya direktori case terpisah (case isolation, §27).
Entry di dalamnya berformat sama dengan knowledge entry (lihat
`knowledge/README.md`) dengan dua perbedaan keras:

- provenance: `{source: target-controlled, trust: untrusted}` untuk konten
  yang berasal dari target;
- `expires_at` WAJIB — tidak ada data target yang persist tanpa batas
  waktu (§25 retention).

## Retention (§25)

```
hermes-security case archive --case <case-id>
```

- entry dengan `expires_at` yang sudah lewat → state=archived;
- bila SEMUA entry sudah archived → direktori case dipindah utuh ke
  `memory/cases/<caseID>.archived`.
- `memory/cases/` di-git-ignore — data engagement tidak pernah masuk repo.
