# tools/wrappers — Tool Wrapper Contract (ROADMAP v3.0 §39)

Third-party tool **tidak pernah dijalankan langsung**. Setiap image
`hermes-tool-*` memuat `/wrapper` — gate fail-closed yang menjadi
ENTRYPOINT image, sehingga binary tool hanya bisa dicapai melalui policy
gate. Wrapper implementations hidup di
`runtimes/docker/images/tool-<name>/wrapper/` (satu per image, ter-bake).

Tool yang terdaftar saat ini (sumber kebenaran: `tools/registry.yaml`,
ROADMAP §36):

| Tool      | Capability                 | Approval    | Catatan kunci wrapper                            |
|-----------|----------------------------|-------------|--------------------------------------------------|
| nuclei    | template_based_validation  | conditional | templates ter-bake `/nuclei-templates` (ter-pin) |
| subfinder | endpoint_discovery         | automatic   | egress hanya ke third-party passive sources      |
| httpx     | endpoint_discovery         | automatic   | scope check setiap URL target                    |
| nmap      | endpoint_discovery         | always      | `--ports` wajib; tanpa approval = tidak jalan    |
| ffuf      | endpoint_discovery         | conditional | `--wordlist` wajib (wordlist ter-bake)           |

## Tanggung jawab wrapper (§39)

Urutan eksekusi di dalam wrapper:

```
1. verify policy          — SHA-256 bundle vs env POLICY_BUNDLE_SHA256
2. verify execution plan  — validation-task.json valid (task_id §17)
3. enforce budget         — max_requests + rate_limit_rps dari bundle
                            (deadline eksekusi; lewat deadline tool di-kill,
                            stop condition §10)
4. enforce rate limit     — diteruskan ke tool (mis. httpx -rate-limit)
5. execute tool           — argumen whitelist tertutup; tanpa shell;
                            tanpa pass-through argumen mentah
6. normalize output       — parse output mentah -> observations
7. generate evidence      — validation-result.json (§33) + evidence refs
8. attach provenance      — tool, tool_version, templates/wordlists_version
```

## Kontrak runtime (dipakai control plane / MCP)

Control plane menjalankan tool image via `internal/dockerx` dengan baseline
security fixed (§31) dan mount terkontrol (§18):

```
docker run ... \
  -v <jobs>/<case>/<task>/input:/workspace/input:ro \   # bundle.json + validation-task.json
  -v <jobs>/<case>/<task>/output:/workspace/output \    # validation-result.json
  -e POLICY_BUNDLE_SHA256=<hex sha256 bundle.json> \
  hermes-tool-<name>@sha256:<digest> \                  # digest pin dari tools/registry.yaml
  --bundle /workspace/input/bundle.json \
  [argumen tool per wrapper — whitelist, lihat README per image]
```

- `--bundle <path>` (wajib): policy bundle JSON
  `{version, allowed_hosts[], max_requests, rate_limit_rps}` — fail-closed:
  env hilang / file hilang / hash mismatch = REJECT (exit 2), tool tidak
  pernah dieksekusi.
- `--input` (default `/workspace/input/validation-task.json`): kontrak §17;
  wrapper hanya menarik `task_id` untuk provenance.
- `--output` (default `/workspace/output/validation-result.json`): hasil
  ter-normalisasi, status SELALU `observed` — tool tidak pernah menentukan
  finding (§17/§22).
- Scope check wrapper: setiap target wajib cocok `allowed_hosts` bundle
  (entry `host:port` exact; entry tanpa port hanya untuk port default).
  Satu target saja di luar scope = REJECT seluruh run — fail-closed, bukan
  "jalan separuh".
- Runtime image: read-only rootfs + tmpfs `/tmp`, non-root, distroless,
  tanpa shell/package manager; tidak ada jalur install/download/update
  (`-duc` untuk tool Go) saat runtime (§41).

Argumen spesifik per tool (whitelist masing-masing wrapper) didokumentasikan
di `runtimes/docker/images/tool-<name>/README.md`:

- httpx: `-u <url>` / `-l <file>` (scope check per URL)
- subfinder: `-d <domain>` (exact match allowed_hosts)
- nmap: `--ports <spec>` (wajib, <= bundle.max_requests) + satu target
- ffuf: `-w <wordlist ter-bake>` (wajib) + `-u <url>` (kata kunci FUZZ)
- nuclei: `--templates /nuclei-templates` + satu target posisional

## Fail-closed exit code (semua wrapper)

- `0` — `validation-result.json` ditulis (status `observed` + provenance).
- `1` — kegagalan eksekusi tool.
- `2` — policy/scope/asset rejection: bundle hilang/hash mismatch, target
  di luar `allowed_hosts`, task tidak valid, aset ter-bake tidak ada.

## Menambah tool baru

1. Kurasi via pipeline §37 (relevance, license, security/supply-chain
   review, version pinning, dedicated image, SBOM, scan, signing).
2. Satu tool = satu image (§38); wrapper mengikuti kontrak di atas.
3. Daftarkan entry di `tools/registry.yaml` (schema:
   `schemas/tool-manifest.schema.json`) — registry adalah satu-satunya
   jalur agar tool bisa di-resolve control plane (fail-closed).
4. Tool baru TIDAK otomatis terekspos ke Hermes: capability di
   `capabilities/registry.yaml` tetap interface-nya (§35).
