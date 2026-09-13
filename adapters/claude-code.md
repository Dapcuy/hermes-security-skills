# Adapter — Claude Code (ROADMAP §44, Phase 13)

Menghubungkan Claude Code ke control plane Hermes Security Skills melalui
MCP stdio (`hermes-security serve --mcp`, ROADMAP §4.3).

## Wiring

Tambahkan server ke Claude Code (user scope, agar tersedia lintas project):

```sh
claude mcp add hermes-security -- hermes-security serve --mcp
```

Dengan flag engagement (scope rules lab + lokasi proxy):

```sh
claude mcp add hermes-security -- hermes-security serve --mcp \
  --scope-file benchmarks/scope-lab.yaml \
  --proxy-url http://127.0.0.1:8080
```

Verifikasi:

```sh
claude mcp list          # hermes-security harus muncul dengan status connected
```

Atau secara manual di `~/.claude.json` / konfigurasi project:

```json
{
  "mcpServers": {
    "hermes-security": {
      "command": "hermes-security",
      "args": ["serve", "--mcp", "--scope-file", "benchmarks/scope-lab.yaml"]
    }
  }
}
```

(Contoh config lengkap: `adapters/hermes.mcp.json`.)

## Catatan

- `hermes-security` harus ada di PATH (atau pakai path absolut ke binary).
- Server berkomunikasi JSON-RPC 2.0 line-delimited di stdio; log non-protokol
  keluar di stderr.
- Tool yang terlihat oleh Claude Code HANYA yang ada di allowlist
  `capabilities/registry.yaml` (§4.3).

## Prasyarat deployment (§4.4) — WAJIB

Enforcement hanya valid bila Claude Code di-deploy dengan restricted tool
access. Prasyarat:

- Claude Code TIDAK diberi docker CLI/docker socket, shell/network tool bebas
  (curl, ncat, dsb.), akses network langsung ke proxy, atau write access ke
  `policy/`, `capabilities/`, `runtimes/`.
- Hanya control-plane MCP tools + read-only `skills/`, `knowledge/`,
  `templates/`.

Bila Claude Code di-deploy dengan akses penuh, seluruh model enforcement
BATAL — adapter ini tidak boleh dipakai untuk operasi nyata (§44).
