package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hermes-security-skills/internal/benchmark"
)

// Subcommand benchmark run (ROADMAP §42, §43 — Phase 11):
//
//	benchmark run --scenarios benchmarks/scenarios.json [--proxy-url URL]
//	               [--scope-file f] [--policy-dir dir] [--out file]
//
// Mode eksekusi otomatis: bila --proxy-url diberikan dan proxy hidup,
// scenario dikirim via POST /execute (mode proxy). Bila proxy tidak jalan,
// evaluasi policy LOKAL (mode policy — tidak ada request ke target).
// Hasil JSON ditulis ke --out (default benchmarks/results/latest.json,
// di-git-ignore) dan seluruh ringkasan ter-audit (§35).

const (
	defaultScenariosPath = "benchmarks/scenarios.json"
	defaultScopeLabFile  = "benchmarks/scope-lab.yaml"
	defaultResultsPath   = "benchmarks/results/latest.json"
)

func cmdBenchmark(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("benchmark: butuh subcommand \"run\"")
	}
	fs := newFlagSet("benchmark run")
	scenariosPath := fs.String("scenarios", defaultScenariosPath, "path scenario set JSON (§42)")
	proxyURL := fs.String("proxy-url", "", "base URL control channel hermes-proxy (opsional; kosong/tidak jalan = mode policy)")
	scopeFile := fs.String("scope-file", defaultScopeLabFile, "scope rules YAML {allowed_hosts} untuk evaluasi policy lokal")
	policyDir := fs.String("policy-dir", defaultPolicyDir, "direktori policy (risk.yaml, limits.yaml)")
	outPath := fs.String("out", defaultResultsPath, "path output JSON hasil run")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	scs, err := benchmark.LoadScenarios(*scenariosPath)
	if err != nil {
		return err
	}
	runner := &benchmark.Runner{
		ProxyURL:    strings.TrimSpace(*proxyURL),
		Scenarios:   scs,
		ScopeFile:   *scopeFile,
		PolicyDir:   *policyDir,
		RegistryDir: defaultRegistry,
	}
	report, err := runner.Run(context.Background())
	if err != nil {
		return err
	}

	printBenchmarkReport(report, *scenariosPath)

	// Tulis hasil JSON (results di-git-ignore — bukan bagian repo).
	if strings.TrimSpace(*outPath) != "" {
		if dir := filepath.Dir(*outPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("benchmark: buat direktori hasil %s: %w", dir, err)
			}
		}
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*outPath, append(data, '\n'), 0o644); err != nil {
			return fmt.Errorf("benchmark: tulis hasil %s: %w", *outPath, err)
		}
		fmt.Printf("hasil JSON : %s\n", filepath.ToSlash(*outPath))
	}

	if err := writeAudit(*auditFile, "benchmark_run", map[string]any{
		"mode": report.Mode, "scenarios": *scenariosPath,
		"total": report.Metrics.Total, "passed": report.Metrics.Passed,
		"failed":                   report.Metrics.Failed,
		"scope_violation_count":    report.Metrics.ScopeViolationCount,
		"destructive_action_count": report.Metrics.DestructiveActionCount,
		"request_count":            report.Metrics.RequestCount,
		"results_out":              filepathToSlash(*outPath),
	}); err != nil {
		return err
	}
	// Run dengan kegagalan = exit non-zero agar CI bisa menangkapnya (§42).
	if report.Metrics.Failed > 0 {
		return fmt.Errorf("benchmark: %d dari %d scenario gagal", report.Metrics.Failed, report.Metrics.Total)
	}
	return nil
}

// printBenchmarkReport menampilkan tabel hasil + metrik §43.
func printBenchmarkReport(report *benchmark.Report, scenariosPath string) {
	mode := report.Mode
	if mode == benchmark.ModePolicy {
		if report.ProxyURL != "" {
			mode += " (proxy tidak jalan — evaluasi policy lokal, tanpa traffic ke target)"
		} else {
			mode += " (tanpa proxy — evaluasi policy lokal)"
		}
	} else {
		mode += " (via control channel " + report.ProxyURL + ")"
	}
	fmt.Printf("benchmark run: %s\n", scenariosPath)
	fmt.Printf("mode: %s\n\n", mode)
	fmt.Printf("  %-28s %-6s %-7s %-9s %-18s %s\n", "SCENARIO", "HASIL", "SCOPE", "RISK", "ACTION", "KETERANGAN")
	for _, r := range report.Results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		}
		scope := "allow"
		if !r.Actual.ScopeAllowed {
			scope = "deny"
		}
		reason := r.Detail
		if reason == "" {
			reason = r.Actual.Reason
		}
		fmt.Printf("  %-28s %-6s %-7s %-9s %-18s %s\n",
			truncateRunes(r.ScenarioID, 28), status, scope, r.Actual.Risk,
			truncateRunes(r.Actual.Action, 18), truncateRunes(reason, 60))
	}
	m := report.Metrics
	fmt.Printf("\nmetrik (ROADMAP §43):\n")
	fmt.Printf("  total=%d passed=%d failed=%d\n", m.Total, m.Passed, m.Failed)
	fmt.Printf("  scope_violation_count=%d (target 0)\n", m.ScopeViolationCount)
	fmt.Printf("  destructive_action_count=%d (target 0)\n", m.DestructiveActionCount)
	fmt.Printf("  request_count=%d\n", m.RequestCount)
}
