package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/capability"
	"hermes-security-skills/internal/mcp"
	"hermes-security-skills/internal/registry"
	"hermes-security-skills/internal/toolregistry"
)

// defaultToolRegistry path Tool Registry (ROADMAP v3.0 §36).
const defaultToolRegistry = "tools/registry.yaml"

// toolRegCount jumlah tool terdaftar (0 bila registry nil — file default
// belum ada di working directory).
func toolRegCount(r *toolregistry.Registry) int {
	if r == nil {
		return 0
	}
	return r.Count()
}

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
	toolRegistryPath := fs.String("tool-registry", defaultToolRegistry, "path Tool Registry YAML (§36; wajib untuk capability provider \"tool\")")
	toolOverridesPath := fs.String("tool-overrides", "", "opsional: file YAML override image tool dev (tool-name: image-ref, §37)")
	manifestPath := fs.String("manifest", defaultManifest, "path image manifest YAML (§13) untuk security.run_validator")
	imageOverridesPath := fs.String("image-overrides", "", "opsional: file YAML override image validator dev (validator-id: image-ref)")
	policyDirFlag := fs.String("policy-dir", defaultPolicyDir, "direktori policy (risk.yaml, limits.yaml)")
	scopeFile := fs.String("scope-file", "", "scope rules YAML {allowed_hosts} untuk scope check in-line")
	cosignKey := fs.String("cosign-key", "", "Cosign public-key reference (alternative to identity+issuer)")
	cosignIdentity := fs.String("cosign-identity", "", "Cosign certificate identity (must be paired with --cosign-issuer)")
	cosignIssuer := fs.String("cosign-issuer", "", "Cosign certificate OIDC issuer (must be paired with --cosign-identity)")
	storePath := fs.String("state-dir", defaultJobsDir, "direktori state approval store (approvals.json)")
	jobsDirFlag := fs.String("jobs-dir", defaultJobsDir, "root jobs untuk cek abort marker (§10) + workspace run_validator/tool run (§18)")
	evidenceDir := fs.String("evidence-dir", defaultEvidenceDir, "direktori evidence hermes-proxy (index event store read-only untuk list_history/inspect_request/response_comparison, §11/§25)")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*mcpMode {
		fmt.Fprintln(os.Stderr, "serve: flag --mcp wajib — satu-satunya mode server yang didukung (ROADMAP 4.3).")
		fmt.Fprintln(os.Stderr, "  usage: hermes-security serve --mcp [--proxy-url URL] [--scope-file file] [--registry file] [--tool-registry file] [--manifest file] [--policy-dir dir] [--state-dir dir] [--jobs-dir dir] [--evidence-dir dir] [--audit-file file]")
		return fmt.Errorf("serve: tanpa --mcp tidak ada server yang dijalankan")
	}

	// Allowlist tool dari capability registry (fail-closed: registry tidak
	// valid = server tidak jalan).
	reg, err := capability.Load(*registryPath)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	// Tool Registry (§36) — fail-closed bila file dikonfigurasi tapi tidak
	// valid. File default opsional: tidak ada = capability provider "tool"
	// ditolak saat dipanggil (fail-closed dengan pesan jelas).
	var toolReg *toolregistry.Registry
	if _, err := os.Stat(*toolRegistryPath); err == nil {
		toolReg, err = toolregistry.Load(*toolRegistryPath)
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
	}
	var toolOverrides map[string]string
	if strings.TrimSpace(*toolOverridesPath) != "" {
		toolOverrides, err = registry.LoadOverrides(*toolOverridesPath)
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
	}
	store := approval.OpenStore(filepath.Join(*storePath, "approvals.json"))
	srv, err := mcp.NewServer(mcp.Config{
		Registry:           reg,
		PolicyDir:          *policyDirFlag,
		ScopeFile:          *scopeFile,
		ProxyURL:           *proxyURL,
		Store:              store,
		JobsDir:            *jobsDirFlag,
		EvidenceDir:        *evidenceDir,
		CosignKeyRef:       *cosignKey,
		CosignIdentity:     *cosignIdentity,
		CosignIssuer:       *cosignIssuer,
		ToolRegistry:       toolReg,
		ToolImageOverrides: toolOverrides,
		ManifestPath:       *manifestPath,
		ImageOverridesPath: *imageOverridesPath,
		Audit:              func(action string, detail map[string]any) error { return writeAudit(*auditFile, action, detail) },
	})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	// Audit entry start (§35: audit log; keputusan tools/call ter-audit
	// per call melalui mcp.Config.Audit).
	if err := writeAudit(*auditFile, "serve_started", map[string]any{
		"mode":              "mcp",
		"proxy_url":         *proxyURL,
		"registry":          *registryPath,
		"tool_registry":     *toolRegistryPath,
		"scope_file":        *scopeFile,
		"state_dir":         *storePath,
		"evidence_dir":      *evidenceDir,
		"tools_allowlisted": reg.Count(),
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "serve: MCP server aktif di stdio (protocol %s) — %d capability dari registry %s\n",
		mcp.ProtocolVersion, reg.Count(), *registryPath)
	fmt.Fprintf(os.Stderr, "serve: tool registry: %s (%d tool terkurasi); manifest: %s\n",
		*toolRegistryPath, toolRegCount(toolReg), *manifestPath)
	fmt.Fprintf(os.Stderr, "serve: proxy control channel: %s; approval store: %s\n", *proxyURL, store.Path())
	fmt.Fprintf(os.Stderr, "serve: event store (read-only): %s\n", *evidenceDir)
	fmt.Fprintln(os.Stderr, "serve: menunggu request JSON-RPC di stdin (EOF untuk keluar, SIGINT/SIGTERM untuk shutdown)...")

	// Graceful shutdown (§35): SIGINT/SIGTERM memicu shutdown terkontrol.
	// Loop serve berjalan di goroutine (loop stdio tidak bisa di-interrupt
	// tanpa menutup stdin); saat sinyal datang, entry audit "shutdown"
	// ditulis utuh SEBELUM proses keluar sehingga audit tidak pernah
	// tertulis setengah. Response JSON-RPC in-flight ditulis dalam satu
	// Flush per baris — tidak ada response yang tertulis separuh.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(os.Stdin, os.Stdout) }()

	reason, serveErr := awaitShutdown(ctx, serveDone)

	// Audit entry shutdown — satu Append atomik per entry (JSONL lengkap
	// atau tidak sama sekali), baik keluar karena EOF maupun sinyal.
	if err := writeAudit(*auditFile, "shutdown", map[string]any{
		"mode":   "mcp",
		"reason": reason,
	}); err != nil {
		return fmt.Errorf("serve: tulis audit shutdown: %w", err)
	}
	if reason == shutdownReasonSignal {
		fmt.Fprintln(os.Stderr, "serve: shutdown (sinyal diterima) — audit entry ditulis.")
		return nil
	}
	// Keluar normal: kembalikan error Serve (biasanya nil saat EOF).
	return serveErr
}

// Alasan shutdown untuk entry audit.
const (
	shutdownReasonEOF    = "stdin_eof"
	shutdownReasonSignal = "signal"
)

// awaitShutdown menunggu loop serve selesai sendiri (EOF stdin) atau
// context shutdown dibatalkan (SIGINT/SIGTERM); mengembalikan alasan untuk
// entry audit plus error loop serve (nil saat sinyal). Jalur context cancel
// bisa diuji langsung tanpa proses/sinyal nyata.
func awaitShutdown(ctx context.Context, serveDone <-chan error) (string, error) {
	select {
	case err := <-serveDone:
		return shutdownReasonEOF, err
	case <-ctx.Done():
		return shutdownReasonSignal, nil
	}
}
