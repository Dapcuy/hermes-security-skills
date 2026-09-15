// Package payload provides a fail-closed, bounded payload registry.
// It only selects already-validated payloads; it never executes or sends them.
package payload

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"hermes-security-skills/internal/policy"
	"hermes-security-skills/internal/risk"
	"hermes-security-skills/internal/yamlmini"
)

type Payload struct {
	ID          string     `json:"id"`
	Category    string     `json:"category"`
	Context     string     `json:"context"`
	Risk        risk.Level `json:"risk"`
	Destructive bool       `json:"destructive"`
	MaxAttempts int        `json:"max_attempts"`
	Source      string     `json:"source"`
	Value       string     `json:"payload"`
}

type Registry struct{ Payloads []Payload }

type Selection struct {
	Context    string
	Risk       risk.Level
	MaxEntries int
	Budget     int
}

// Load parses and validates a registry. Invalid input never produces a partial registry.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("payload: read %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("payload: parse %s: %w", path, err)
	}
	for k := range doc {
		if k != "version" && k != "payloads" {
			return nil, fmt.Errorf("payload: unknown top-level field %q", k)
		}
	}
	v, ok := doc["version"].(int)
	if !ok || v != 1 {
		return nil, fmt.Errorf("payload: version must be integer 1")
	}
	raw, ok := doc["payloads"]
	if !ok {
		return nil, fmt.Errorf("payload: payloads is required")
	}
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("payload: payloads must be a non-empty sequence")
	}
	out := &Registry{Payloads: make([]Payload, 0, len(items))}
	seen := map[string]bool{}
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("payload: payloads[%d] must be a mapping", i)
		}
		p, err := parsePayload(m, i)
		if err != nil {
			return nil, err
		}
		if seen[p.ID] {
			return nil, fmt.Errorf("payload: duplicate id %q", p.ID)
		}
		seen[p.ID] = true
		out.Payloads = append(out.Payloads, p)
	}
	return out, nil
}

func parsePayload(m map[string]any, i int) (Payload, error) {
	allowed := map[string]bool{"id": true, "category": true, "context": true, "risk": true, "destructive": true, "max_attempts": true, "source": true, "payload": true, "value": true}
	for k := range m {
		if !allowed[k] {
			return Payload{}, fmt.Errorf("payload: payloads[%d]: unknown field %q", i, k)
		}
	}
	str := func(k string) (string, error) {
		v, ok := m[k]
		if !ok {
			return "", fmt.Errorf("payload: payloads[%d].%s is required", i, k)
		}
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return "", fmt.Errorf("payload: payloads[%d].%s must be a non-empty string", i, k)
		}
		return strings.TrimSpace(s), nil
	}
	var p Payload
	var err error
	if p.ID, err = str("id"); err != nil {
		return p, err
	}
	if p.Category, err = str("category"); err != nil {
		return p, err
	}
	if p.Context, err = str("context"); err != nil {
		return p, err
	}
	p.Context = strings.ToLower(p.Context)
	rawRisk, ok := m["risk"].(string)
	if !ok {
		return p, fmt.Errorf("payload: payloads[%d].risk is required and must be string", i)
	}
	p.Risk = risk.Level(strings.ToLower(strings.TrimSpace(rawRisk)))
	if _, err := risk.DefaultAction(p.Risk); err != nil {
		return p, fmt.Errorf("payload: payloads[%d]: %w", i, err)
	}
	b, ok := m["destructive"].(bool)
	if !ok || b {
		return p, fmt.Errorf("payload: payloads[%d].destructive must be false", i)
	}
	p.Destructive = b
	n, ok := m["max_attempts"].(int)
	if !ok || n < 1 {
		return p, fmt.Errorf("payload: payloads[%d].max_attempts must be positive integer", i)
	}
	p.MaxAttempts = n
	if p.Source, err = str("source"); err != nil {
		return p, err
	}
	if v, ok := m["payload"]; ok {
		if _, both := m["value"]; both {
			return p, fmt.Errorf("payload: payloads[%d] must not define both payload and value", i)
		}
		p.Value, ok = v.(string)
		if !ok {
			return p, fmt.Errorf("payload: payloads[%d].payload must be string", i)
		}
	} else if v, ok := m["value"]; ok {
		p.Value, ok = v.(string)
		if !ok {
			return p, fmt.Errorf("payload: payloads[%d].value must be string", i)
		}
	} else {
		return p, fmt.Errorf("payload: payloads[%d].payload is required", i)
	}
	p.Value = strings.TrimSpace(p.Value)
	if p.Value == "" || unsafeText(p.Category+" "+p.Source+" "+p.Value) {
		return p, fmt.Errorf("payload: payloads[%d] denied by safety policy", i)
	}
	return p, nil
}

func unsafeText(s string) bool {
	s = strings.ToLower(s)
	for _, term := range []string{"destruct", "credential", "password", "brute force", "credential-stuff", "exfil", "data theft", "reverse shell", "drop table", "delete from", "rm -rf"} {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}

// Select returns deterministic, risk-capped, policy-bounded payloads for the caller.
func (r *Registry) Select(s Selection, lim *policy.PolicyLimits) ([]Payload, error) {
	if r == nil || lim == nil {
		return nil, fmt.Errorf("payload: registry and policy limits are required")
	}
	if lim.MaxEntriesPerTask < 1 || lim.MaxRequestsTotal < 1 || lim.RateLimitRPS < 1 || lim.MaxConcurrency < 1 || !lim.StopOn429 || !lim.StopOnRepeated5xx || lim.DestructivePayloads != "deny" || lim.ExfiltrationPayloads != "deny" || lim.CredentialAttackLists != "deny" {
		return nil, fmt.Errorf("payload: unsafe or invalid policy limits")
	}
	ctx := strings.TrimSpace(strings.ToLower(s.Context))
	if ctx == "" {
		return nil, fmt.Errorf("payload: selection context is required")
	}
	if _, err := risk.DefaultAction(s.Risk); err != nil {
		return nil, err
	}
	if s.Budget < 1 || s.Budget > lim.MaxRequestsTotal {
		return nil, fmt.Errorf("payload: budget exceeds policy")
	}
	max := s.MaxEntries
	if max < 1 {
		max = lim.MaxEntriesPerTask
	}
	if max > lim.MaxEntriesPerTask {
		max = lim.MaxEntriesPerTask
	}
	if max > s.Budget {
		max = s.Budget
	}
	candidates := make([]Payload, 0)
	for _, p := range r.Payloads {
		if p.Risk == risk.LevelCritical || p.Destructive || p.MaxAttempts > s.Budget || unsafeText(p.Category+" "+p.Source+" "+p.Value) {
			continue
		}
		if p.Risk != s.Risk && !(s.Risk == risk.LevelHigh && p.Risk == risk.LevelLow) && !(s.Risk == risk.LevelMedium && p.Risk == risk.LevelLow) {
			continue
		}
		if p.Context != ctx && p.Context != "any" {
			continue
		}
		candidates = append(candidates, p)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		ei := candidates[i].Context == ctx
		ej := candidates[j].Context == ctx
		if ei != ej {
			return ei
		}
		ri := rank(candidates[i].Risk)
		rj := rank(candidates[j].Risk)
		if ri != rj {
			return ri < rj
		}
		return candidates[i].ID < candidates[j].ID
	})
	if len(candidates) > max {
		candidates = candidates[:max]
	}
	return candidates, nil
}
func rank(l risk.Level) int {
	switch l {
	case risk.LevelLow:
		return 1
	case risk.LevelMedium:
		return 2
	case risk.LevelHigh:
		return 3
	default:
		return 4
	}
}
