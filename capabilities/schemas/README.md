# Capability Registry — Format dan Konvensi

File `capabilities/registry.yaml` adalah sumber kebenaran untuk capability
abstraction (ROADMAP §5). Skill meminta *capability*, bukan tool; provider
ditentukan oleh registry ini (ROADMAP §4.1).

## Format: YAML subset sederhana

Registry sengaja dibatasi ke subset YAML yang bisa dibaca parser sederhana
berbasis Go-stdlib (parser baris, bukan YAML library penuh). Yang **boleh**:

- mapping (map) dengan indentasi spasi (2 spasi per level)
- sequence (seq) dengan `-`
- scalar: string, int, bool
- komentar `#` (hanya di awal baris)

Yang **dilarang** (akan ditolak parser / linter):

- anchor dan alias (`&x`, `*x`)
- flow style (`{a: 1}`, `[1, 2]`)
- multiline block scalar (`|`, `>`)
- key duplikat, tab sebagai indentasi
- tipe kompleks (date, float eksponensial, dsb.)

Prinsipnya: **fail-closed** — entry yang tidak bisa di-parse atau field yang
tidak dikenal membuat registry ditolak seluruhnya, bukan di-skip diam-diam
(ROADMAP §5.1).

## Field yang valid

Top-level:

| Field                | Tipe   | Wajib | Keterangan |
|----------------------|--------|-------|------------|
| `version`            | int    | ya    | Versi format registry. |
| `fallback_semantics` | string | ya    | Harus `fail-closed` (ROADMAP §5.1): provider utama unavailable = capability gagal eksplisit; policy denial = stop; tanpa silent degrade. |
| `capabilities`       | map    | ya    | Daftar capability, key = ID capability. |

Per capability:

| Field               | Tipe   | Wajib | Nilai valid | Keterangan |
|---------------------|--------|-------|-------------|------------|
| `risk`              | string | ya    | `low` / `medium` / `high` / `critical` | Menentukan default action di `policy/risk.yaml` (ROADMAP §8). |
| `default_provider`  | string | ya    | `proxy` / `docker` / `local` | Proxy = satu-satunya egress; docker = validator `network=none`; local = komputasi murni tanpa side effect (ROADMAP §5.2, §5.3). |
| `requires_scope`    | bool   | ya    | `true` / `false` | `true` berarti target wajib lolos scope validation (ROADMAP §8). `false` hanya untuk operasi yang tidak menyentuh target (mis. baca event store, analisis dokumen lokal). |
| `requires_network`  | bool   | ya    | `true` / `false` | `true` hanya boleh dilayani proxy provider (ROADMAP §5.2). |
| `requires_approval` | string | tidak | `conditional` / `always` | Ada hanya untuk capability aktif yang bisa menyentuh state target (mis. `request_replay` memakai `conditional`; `nmap_scan` memakai `always` — port scanning wajib approval sebelum eksekusi). |
| `image`             | string | tidak | nama image terkurasi | Wajib untuk capability dengan `default_provider: docker` (mis. `hermes-validator-openapi`). Versi/digest image dicatat di execution plan (ROADMAP §14), bukan di registry. |

## Cara menambah capability baru

1. Pastikan operasinya benar-benar *capability* (abstraksi operasi), bukan
   nama tool. Tool tidak boleh muncul di registry (ROADMAP §4.1, §7.1).
2. Tentukan provider sesuai aturan §5:
   - mengirim traffic ke target → `proxy` (satu-satunya jalur egress);
   - validasi deterministik pada data yang sudah ada → `docker` + image
     terkurasi dengan `network=none`;
   - parsing/komputasi murni tanpa side effect → `local`.
3. Tentukan `risk` awal konservatif; hubungkan ke `policy/risk.yaml`.
4. Tambahkan entry baru di `capabilities:` dengan semua field wajib.
5. Jika `default_provider: docker`, pastikan image-nya terdaftar di
   `runtimes/docker/images/` dan di-build/ter-sign lewat pipeline (ROADMAP §36).
6. Jalankan linter/CI; registry yang tidak lolos validasi membuat semua
   capability gagal (fail-closed), bukan hanya yang baru.
7. Capability baru dengan `requires_network: true` hanya boleh aktif setelah
   egress melalui hermes-proxy tersedia (post-MVP, ROADMAP §5.2, §21).

File registry ini read-only dari sudut pandang Hermes; perubahan tercatat di
audit log (lihat `policy/README.md`, ROADMAP §4.4, §8 Policy Integrity).
