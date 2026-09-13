# Adapter — Cursor (ROADMAP §44, Phase 13)

Menghubungkan Cursor ke control plane Hermes Security Skills melalui MCP
stdio (`hermes-security serve --mcp`, ROADMAP §4.3).

## Wiring

Buat/edit file `.cursor/mcp.json` di project (atau `~/.cursor/mcp.json`
untuk global):

```json
{
  "mcpServers": {
    "hermes-security": {
      "command": "hermes-security",
      "args": [
        "serve", "--mcp",
        "--scope-file", "benchmarks/scope-lab.yaml",
        "--proxy-url", "http://127.0.0.1:8080"
      ],
      "env": {}
    }
  }
}
```

Contoh config minimal tanpa flag tambahan: `adapters/hermes.mcp.json`.

Setelah file disimpan, buka Cursor → Settings → MCP & Integrations →
server `hermes-security` harus berstatus connected (daftar tool terisi dari
allowlist `capabilities/registry.yaml`).

## Catatan

- `hermes-security` harus ada di PATH; bila tidak, pakai path absolut di
  field `command`.
- Cursor Agent harus di-set memakai tool `mcp__hermes-security__*` untuk
  semua operasi capability — jangan memberi Cursor tool HTTP/shell sendiri.

## Prasyarat deployment (§4.4) — WAJIB

Enforcement hanya valid bila Cursor di-deploy dengan restricted tool access:

- Cursor Agent TIDAK diberi akses shell/terminal bebas, docker CLI/socket,
  network tool (fetch/curl), atau write access ke `policy/`,
  `capabilities/`, `runtimes/`.
- Agent settings: matikan (deny) built-in tools yang membuka jalur
  network/shell langsung; hanya MCP tools control plane yang diizinkan.

Bila pembatasan tool tidak bisa dijamin di konfigurasi Cursor Anda, adapter
ini tidak didukung untuk operasi nyata (§44) — gunakan hanya untuk
reasoning dry-run di lab.
