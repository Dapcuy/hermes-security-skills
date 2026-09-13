package main

import (
	"fmt"
	"os"
	"path/filepath"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/capability"
	"hermes-security-skills/internal/mcp"
)

// cmdServe menjalankan MCP server mode — enforcement path (ROADMAP 4.3, 35).
//
//	hermes-security serve --mcp [--proxy-url URL] [--scope-file f] ...
//
// JSON-RPC 2.0 line-delimited over stdio: request dari stdin, response ke
// stdout. Semua output non-protokol ke stderr. Flag --mcp wajib; tanpa itu
// usage ditampilkan dan TIDAK ada server yang jalan (fail-closed).
//
// In-line enforcement (§4.3): setiap tools/call berisiko dievaluasi dulu
// di proses ini (scope + risk + approval + abort marker) SEBELUM proxy
// dikontak — Hermes tidak punya jalur lain ke provider.
func cmdServe(args []string) error {
	fs := newFlagSet("serve")
	mcpMode := fs.Bool("mcp", false, "jalankan MCP server (JSON-RPC 2.0 over stdio) — WAJIB")
	proxyURL := fs.String("proxy-url", "http://127.0.0.1:8080", "base URL control channel hermes-proxy (POST /execute)")
	registryPath := fs.String("registry", defaultRegistry, "path capability registry YAML (allowlist tool, §4.3)")
	policyDirFlag := fs.String("policy-dir", defaultPolicyDir, "direktori policy (risk.yaml, limits.yaml)")
	scopeFile := fs.String("scope-file", "", "scope rules YAML {allowed_hosts} untuk scope check in-line")
	storePath := fs.String("state-dir", defaultJobsDir, "direktori state approval store (approvals.json)")
	jobsDirFlag := fs.String("jobs-dir", defaultJobsDir, "root jobs untuk cek abort marker (§10)")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*mcpMode {
		fmt.Fprintln(os.Stderr, "serve: flag --mcp wajib — satu-satunya mode server yang didukung (ROADMAP 4.3).")
		fmt.Fprintln(os.Stderr, "  usage: hermes-security serve --mcp [--proxy-url URL] [--scope-file file] [--registry file] [--policy-dir dir] [--state-dir dir] [--jobs-dir dir] [--audit-file file]")
		return fmt.Errorf("serve: tanpa --mcp tidak ada server yang dijalankan")
	}

	// Allowlist tool dari capability registry (fail-closed: registry tidak
	// valid = server tidak jalan).
	reg, err := capability.Load(*registryPath)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	store := approval.OpenStore(filepath.Join(*storePath, "approvals.json"))
	srv, err := mcp.NewServer(mcp.Config{
		Registry:  reg,
		PolicyDir: *policyDirFlag,
		ScopeFile: *scopeFile,
		ProxyURL:  *proxyURL,
		Store:     store,
		JobsDir:   *jobsDirFlag,
		Audit:     func(action string, detail map[string]any) error { return writeAudit(*auditFile, action, detail) },
	})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	// Audit entry start (§35: audit log; keputusan tools/call ter-audit
	// per call melalui mcp.Config.Audit).
	if err := writeAudit(*auditFile, "serve_started", map[string]any{
		"mode":        "mcp",
		"proxy_url":   *proxyURL,
		"registry":    *registryPath,
		"scope_file":  *scopeFile,
		"state_dir":   *storePath,
		"tools_allowlisted": reg.Count(),
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "serve: MCP server aktif di stdio (protocol %s) — %d tool dari registry %s\n",
		mcp.ProtocolVersion, reg.Count(), *registryPath)
	fmt.Fprintf(os.Stderr, "serve: proxy control channel: %s; approval store: %s\n", *proxyURL, store.Path())
	fmt.Fprintln(os.Stderr, "serve: menunggu request JSON-RPC di stdin (EOF untuk keluar)...")

	// Jalankan sampai stdin EOF. stdout HANYA berisi response JSON-RPC.
	return srv.Serve(os.Stdin, os.Stdout)
}
