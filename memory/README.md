# Memory (ROADMAP §27, §25)

```
memory/
├── global/   — memori lintas-engagement (MVP: kosong)
└── cases/    — case memory per engagement: memory/cases/<caseID>/
```

## Prinsip owner — apa yang boleh masuk memory

```
Memory HANYA untuk:
  - state kasus            (status engagement, finding, workspace)
  - keputusan              (keputusan human: approval, adopsi, eskalasi)
  - evidence reference     (hash + path + provenance, bukan salinan mentah)
  - approval               (scope, budget, expiry, revocation)

Memory BUKAN tempat menyimpan METODOLOGI security.
Metodologi hidup di skills/ - curated, versioned, lolos linter (§7, §7.1).
Pelajaran yang masih terikat satu kasus = entry case memory di bawah;
bila pelajaran ternyata generalisasi metodologi, tulis sebagai SKILL.md
baru (atau perbaiki skill yang ada), bukan sebagai entry memory.
```

Alasan: skill adalah sumber kebenaran metodologi yang direview dan
ter-versioning; memory menumpuk state engagement yang berumur pendek.
Mencampur keduanya membuat metodologi mengendap di tempat yang tidak
direview dan tidak lulus linter.

## Case memory

Setiap engagement punya direktori case terpisah (case isolation, §27).
Entry di dalamnya berformat sama dengan knowledge entry (lihat
`knowledge/README.md`) dengan dua perbedaan keras:

- provenance: `{source: target-controlled, trust: untrusted}` untuk konten
  yang berasal dari target;
- `expires_at` WAJIB — tidak ada data target yang persist tanpa batas
  waktu (§25 retention).

Entry pelajaran spesifik-kasus (mis. `memory/cases/juice-demo/`) juga
hidup di sini — pelajaran yang terikat konteks satu engagement, bukan
metodologi umum.

## Retention (§25)

```
hermes-security case archive --case <case-id>
```

- entry dengan `expires_at` yang sudah lewat → state=archived;
- bila SEMUA entry sudah archived → direktori case dipindah utuh ke
  `memory/cases/<caseID>.archived`.
- `memory/cases/` di-git-ignore — data engagement tidak pernah masuk repo.
