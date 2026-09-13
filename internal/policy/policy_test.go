package policy

import (
	"os"
	"path/filepath"
	"testing"

	"hermes-security-skills/internal/risk"
)

const riskFixture = `
version: 1

default_action:
  low: automatic
  medium: conditional
  high: approval_required
  critical: disabled
`

const limitsFixture = `
version: 1

payload_policy:
  max_entries_per_task: 100
  max_requests_total: 50
  rate_limit_rps: 1
  max_concurrency: 1
  stop_on_429: true
  stop_on_repeated_5xx: true
  destructive_payloads: deny
  exfiltration_payloads: deny
  credential_attack_lists: deny
`

func writePolicyDir(t *testing.T, riskYAML, limitsYAML string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "risk.yaml"), []byte(riskYAML), 0o600); err != nil {
		t.Fatalf("tulis risk.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "limits.yaml"), []byte(limitsYAML), 0o600); err != nil {
		t.Fatalf("tulis limits.yaml: %v", err)
	}
	return dir
}

func TestLoadDir(t *testing.T) {
	dir := writePolicyDir(t, riskFixture, limitsFixture)
	p, err := Load(dir)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if p.Risk == nil || p.Limits == nil {
		t.Fatal("Risk/Limits tidak boleh nil")
	}
	lim := p.Limits
	if lim.MaxEntriesPerTask != 100 || lim.MaxRequestsTotal != 50 ||
		lim.RateLimitRPS != 1 || lim.MaxConcurrency != 1 {
		t.Errorf("limits int tidak sesuai: %+v", lim)
	}
	if !lim.StopOn429 || !lim.StopOnRepeated5xx {
		t.Errorf("stop conditions harus true: %+v", lim)
	}
	if lim.DestructivePayloads != "deny" || lim.ExfiltrationPayloads != "deny" || lim.CredentialAttackLists != "deny" {
		t.Errorf("kategori payload harus deny: %+v", lim)
	}
}

func TestEvaluate(t *testing.T) {
	dir := writePolicyDir(t, riskFixture, limitsFixture)
	p, err := Load(dir)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	cases := []struct {
		lvl  risk.Level
		want risk.Action
	}{
		{risk.LevelLow, risk.ActionAutomatic},
		{risk.LevelMedium, risk.ActionConditional},
		{risk.LevelHigh, risk.ActionApprovalRequired},
		{risk.LevelCritical, risk.ActionDisabled},
	}
	for _, tc := range cases {
		got, err := p.Evaluate("request_replay", tc.lvl)
		if err != nil {
			t.Fatalf("Evaluate(%s) error: %v", tc.lvl, err)
		}
		if got != tc.want {
			t.Errorf("Evaluate(%s) = %s, mau %s", tc.lvl, got, tc.want)
		}
	}
	// Risk class tidak dikenal = fail-closed.
	if _, err := p.Evaluate("request_replay", risk.Level("bogus")); err == nil {
		t.Error("Evaluate risk tak dikenal harus error")
	}
	if _, err := p.Evaluate("request_replay", ""); err == nil {
		t.Error("Evaluate risk kosong harus error")
	}
}

func TestEvaluateFallbackTanpaRiskFile(t *testing.T) {
	p := &Policy{Limits: &PolicyLimits{}}
	got, err := p.Evaluate("cap", risk.LevelMedium)
	if err != nil {
		t.Fatalf("Evaluate fallback error: %v", err)
	}
	if got != risk.ActionConditional {
		t.Errorf("fallback = %s, mau conditional", got)
	}
	if _, err := p.Evaluate("cap", risk.Level("x")); err == nil {
		t.Error("fallback dengan level tak dikenal harus error")
	}
}

func TestLoadFailClosed(t *testing.T) {
	// risk.yaml: risk class tidak dikenal.
	badRisk := "default_action:\n  low: automatic\n  unknown: automatic\n"
	if _, err := LoadRisk(writeFileTemp(t, "risk.yaml", badRisk)); err == nil {
		t.Error("risk class tidak dikenal harus error")
	}
	// risk.yaml: action tidak valid.
	badAction := "default_action:\n  low: whenever_you_like\n"
	if _, err := LoadRisk(writeFileTemp(t, "risk.yaml", badAction)); err == nil {
		t.Error("action tidak valid harus error")
	}
	// risk.yaml: nilai bukan string.
	nonStr := "default_action:\n  low: true\n"
	if _, err := LoadRisk(writeFileTemp(t, "risk.yaml", nonStr)); err == nil {
		t.Error("action bool harus ditolak")
	}
	// limits.yaml: angka <= 0.
	badInt := "payload_policy:\n  max_entries_per_task: 0\n  max_requests_total: 50\n  rate_limit_rps: 1\n  max_concurrency: 1\n  stop_on_429: true\n  stop_on_repeated_5xx: true\n  destructive_payloads: deny\n  exfiltration_payloads: deny\n  credential_attack_lists: deny\n"
	if _, err := LoadLimits(writeFileTemp(t, "limits.yaml", badInt)); err == nil {
		t.Error("angka <= 0 harus error")
	}
	// limits.yaml: stop condition false (melonggarkan guardrail).
	badBool := "payload_policy:\n  max_entries_per_task: 100\n  max_requests_total: 50\n  rate_limit_rps: 1\n  max_concurrency: 1\n  stop_on_429: false\n  stop_on_repeated_5xx: true\n  destructive_payloads: deny\n  exfiltration_payloads: deny\n  credential_attack_lists: deny\n"
	if _, err := LoadLimits(writeFileTemp(t, "limits.yaml", badBool)); err == nil {
		t.Error("stop_on_429 false harus error")
	}
	// limits.yaml: kategori payload bukan deny.
	badDeny := "payload_policy:\n  max_entries_per_task: 100\n  max_requests_total: 50\n  rate_limit_rps: 1\n  max_concurrency: 1\n  stop_on_429: true\n  stop_on_repeated_5xx: true\n  destructive_payloads: allow\n  exfiltration_payloads: deny\n  credential_attack_lists: deny\n"
	if _, err := LoadLimits(writeFileTemp(t, "limits.yaml", badDeny)); err == nil {
		t.Error("destructive_payloads allow harus error")
	}
	// limits.yaml: field wajib hilang.
	missing := "payload_policy:\n  max_requests_total: 50\n"
	if _, err := LoadLimits(writeFileTemp(t, "limits.yaml", missing)); err == nil {
		t.Error("field wajib hilang harus error")
	}
	// Direktori tanpa file.
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("Load dir kosong harus error")
	}
}

func writeFileTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis %s: %v", name, err)
	}
	return path
}
