# Adapters — Multi-Agent Compatibility (ROADMAP §44, Phase 13)

## Prinsip: client-neutral core

Security methodology project ini TIDAK bergantung pada satu agent client.
Pembagiannya:

```
Client-Neutral Core (bagian repo ini, sama untuk semua client):
  skills/          metodologi keamanan (teach)
  schemas/         kontrak data (execution plan, evidence, finding, ...)
  ROUTING.md       pemilihan skill berdasarkan konteks
  policy/          authorization, scope, risk, approval, limits
  capabilities/    registry capability (abstraksi operasi)
  knowledge/       knowledge base (canonical / proposed / reviewed)
  memory/          case memory per engagement
  benchmarks/      scenario lab + hasil run (§42)

Adapter (per client — HANYA konfigurasi koneksi, tanpa logika):
  hermes.mcp.json  config MCP client generic
  claude-code.md   wiring Claude Code
  cursor.md        wiring Cursor
```

## Satu-satunya jalur enforcement

Semua adapter memakai jalur yang sama:

```
<agent client> ──stdio (JSON-RPC 2.0)──► hermes-security serve --mcp
                                             │
                                             ├─ scope check   (in-line)
                                             ├─ risk classify (in-line)
                                             ├─ approval      (in-line)
                                             └─ POST /execute ─► hermes-proxy
```

Agent TIDAK PERNAH memanggil proxy, Docker, atau target secara langsung —
satu-satunya pintu adalah MCP server control plane (§4.3). Adapter hanya
menunjuk binary `hermes-security` dan argumennya; tidak ada adapter yang
membawa policy atau logic.

## Prasyarat deployment (§4.4) — BERLAKU UNTUK SEMUA ADAPTER

Enforcement hanya valid bila agent client di-deploy dengan restricted tool
access. Agent TIDAK diberi:

- docker CLI / docker socket
- shell atau network tool bebas (curl, ncat, dsb.)
- akses network langsung / koneksi langsung ke proxy container
- write access ke `policy/`, `capabilities/`, `runtimes/`

Agent HANYA diberi:

- control-plane MCP tools (dari `capabilities/registry.yaml`)
- read-only access ke `skills/`, `knowledge/`, `templates/`

**Adapter yang tidak bisa menjamin restricted tool access tidak didukung**
(§44). Jika client tidak mendukung pembatasan tool per-agent, jangan
menghubungkannya ke control plane untuk operasi nyata.

## Daftar adapter

| File               | Client      | Bentuk wiring                          |
|--------------------|-------------|----------------------------------------|
| `hermes.mcp.json`  | generic MCP | file config `mcpServers` stdio         |
| `claude-code.md`   | Claude Code | `claude mcp add ...` (stdio)           |
| `cursor.md`        | Cursor      | `.cursor/mcp.json` (stdio)             |

Semua adapter menjalankan command yang sama:
`hermes-security serve --mcp` dengan flag tambahan sesuai engagement
(`--scope-file`, `--proxy-url`, `--policy-dir`).
