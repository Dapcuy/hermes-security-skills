// Package policy memuat policy files (policy/risk.yaml + policy/limits.yaml)
// dan mengevaluasi action untuk sebuah capability (ROADMAP 8, 22).
//
// Fail-closed: file tidak parseable, field wajib hilang, tipe salah,
// atau nilai yang melonggarkan guardrail default = error.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hermes-security-skills/internal/risk"
	"hermes-security-skills/internal/yamlmini"
)

// PolicyLimits adalah ceiling payload & request policy (ROADMAP 22).
type PolicyLimits struct {
	MaxEntriesPerTask     int    `json:"max_entries_per_task"`
	MaxRequestsTotal      int    `json:"max_requests_total"`
	RateLimitRPS          int    `json:"rate_limit_rps"`
	MaxConcurrency        int    `json:"max_concurrency"`
	StopOn429             bool   `json:"stop_on_429"`
	StopOnRepeated5xx     bool   `json:"stop_on_repeated_5xx"`
	DestructivePayloads   string `json:"destructive_payloads"`
	ExfiltrationPayloads  string `json:"exfiltration_payloads"`
	CredentialAttackLists string `json:"credential_attack_lists"`
}

// RiskPolicy memuat mapping default action per risk class dari risk.yaml.
type RiskPolicy struct {
	DefaultAction map[string]string // "low" -> "automatic", dst.
}

// Policy gabungan risk + limits dari satu direktori policy.
type Policy struct {
	Risk   *RiskPolicy
	Limits *PolicyLimits
}

// Load membaca risk.yaml dan limits.yaml dari direktori dir.
func Load(dir string) (*Policy, error) {
	rp, err := LoadRisk(filepath.Join(dir, "risk.yaml"))
	if err != nil {
		return nil, err
	}
	lim, err := LoadLimits(filepath.Join(dir, "limits.yaml"))
	if err != nil {
		return nil, err
	}
	return &Policy{Risk: rp, Limits: lim}, nil
}

// Evaluate memetakan (capability, risk) ke Action.
// Action diambil dari default_action risk.yaml (sumber kebenaran policy);
// risk class tidak dikenal = error fail-closed.
func (p *Policy) Evaluate(capability string, lvl risk.Level) (risk.Action, error) {
	if strings.TrimSpace(string(lvl)) == "" {
		return "", fmt.Errorf("policy: risk kosong untuk capability %q", capability)
	}
	if p.Risk != nil && p.Risk.DefaultAction != nil {
		if act, ok := p.Risk.DefaultAction[string(lvl)]; ok {
			a := risk.Action(act)
			if !isValidAction(a) {
				return "", fmt.Errorf("policy: action %q tidak dikenal untuk risk %q", act, lvl)
			}
			return a, nil
		}
		return "", fmt.Errorf("policy: risk class %q tidak ada di default_action (capability %q)", lvl, capability)
	}
	// Fallback ke default hardcoded bila risk.yaml tidak memuat mapping.
	return risk.DefaultAction(lvl)
}

func isValidAction(a risk.Action) bool {
	switch a {
	case risk.ActionAutomatic, risk.ActionConditional, risk.ActionApprovalRequired, risk.ActionDisabled:
		return true
	}
	return false
}

// LoadRisk mem-parse policy/risk.yaml.
func LoadRisk(path string) (*RiskPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: baca %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	raw, ok := doc["default_action"]
	if !ok {
		return nil, fmt.Errorf("policy: %s: field 'default_action' tidak ada", path)
	}
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("policy: %s: 'default_action' harus map tidak kosong", path)
	}
	rp := &RiskPolicy{DefaultAction: make(map[string]string, len(m))}
	for k, v := range m {
		lvl := risk.Level(strings.ToLower(k))
		if _, err := risk.DefaultAction(lvl); err != nil {
			return nil, fmt.Errorf("policy: %s: risk class tidak dikenal %q", path, k)
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("policy: %s: default_action.%s harus string", path, k)
		}
		rp.DefaultAction[string(lvl)] = s
	}
	// Nilai action divalidasi saat Evaluate; validasi awal cepat di sini.
	for k, v := range rp.DefaultAction {
		if !isValidAction(risk.Action(v)) {
			return nil, fmt.Errorf("policy: %s: default_action.%s = %q bukan action yang valid", path, k, v)
		}
	}
	return rp, nil
}

// LoadLimits mem-parse policy/limits.yaml. Fail-closed: field hilang,
// angka <= 0, stop condition false, atau kategori payload bukan "deny"
// dianggap policy tidak valid.
func LoadLimits(path string) (*PolicyLimits, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: baca %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	raw, ok := doc["payload_policy"]
	if !ok {
		return nil, fmt.Errorf("policy: %s: field 'payload_policy' tidak ada", path)
	}
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("policy: %s: 'payload_policy' harus map tidak kosong", path)
	}
	lim := &PolicyLimits{}
	if lim.MaxEntriesPerTask, err = requirePositiveInt(m, "max_entries_per_task", path); err != nil {
		return nil, err
	}
	if lim.MaxRequestsTotal, err = requirePositiveInt(m, "max_requests_total", path); err != nil {
		return nil, err
	}
	if lim.RateLimitRPS, err = requirePositiveInt(m, "rate_limit_rps", path); err != nil {
		return nil, err
	}
	if lim.MaxConcurrency, err = requirePositiveInt(m, "max_concurrency", path); err != nil {
		return nil, err
	}
	if lim.StopOn429, err = requireTrueBool(m, "stop_on_429", path); err != nil {
		return nil, err
	}
	if lim.StopOnRepeated5xx, err = requireTrueBool(m, "stop_on_repeated_5xx", path); err != nil {
		return nil, err
	}
	if lim.DestructivePayloads, err = requireDeny(m, "destructive_payloads", path); err != nil {
		return nil, err
	}
	if lim.ExfiltrationPayloads, err = requireDeny(m, "exfiltration_payloads", path); err != nil {
		return nil, err
	}
	if lim.CredentialAttackLists, err = requireDeny(m, "credential_attack_lists", path); err != nil {
		return nil, err
	}
	return lim, nil
}

func requirePositiveInt(m map[string]any, field, path string) (int, error) {
	v, ok := m[field]
	if !ok {
		return 0, fmt.Errorf("policy: %s: payload_policy.%s wajib ada", path, field)
	}
	n, ok := v.(int)
	if !ok {
		return 0, fmt.Errorf("policy: %s: payload_policy.%s harus int", path, field)
	}
	if n <= 0 {
		return 0, fmt.Errorf("policy: %s: payload_policy.%s harus > 0 (dapat %d)", path, field, n)
	}
	return n, nil
}

func requireTrueBool(m map[string]any, field, path string) (bool, error) {
	v, ok := m[field]
	if !ok {
		return false, fmt.Errorf("policy: %s: payload_policy.%s wajib ada", path, field)
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("policy: %s: payload_policy.%s harus bool", path, field)
	}
	if !b {
		// Stop condition false = melonggarkan guardrail default -> tolak.
		return false, fmt.Errorf("policy: %s: payload_policy.%s harus true (guardrail tidak boleh dilonggarkan)", path, field)
	}
	return b, nil
}

func requireDeny(m map[string]any, field, path string) (string, error) {
	v, ok := m[field]
	if !ok {
		return "", fmt.Errorf("policy: %s: payload_policy.%s wajib ada", path, field)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("policy: %s: payload_policy.%s harus string", path, field)
	}
	if s != "deny" {
		return "", fmt.Errorf("policy: %s: payload_policy.%s harus \"deny\" (dapat %q)", path, field, s)
	}
	return s, nil
}
