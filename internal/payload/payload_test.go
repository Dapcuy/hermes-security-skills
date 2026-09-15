package payload

import (
	"os"
	"path/filepath"
	"testing"

	"hermes-security-skills/internal/policy"
	"hermes-security-skills/internal/risk"
)

const registryFixture = `version: 1
payloads:
  - id: sql-basic
    category: sql-injection
    context: query
    risk: low
    destructive: false
    max_attempts: 2
    source: curated
    payload: "' OR '1'='1"
  - id: header-safe
    category: header
    context: header
    risk: medium
    destructive: false
    max_attempts: 1
    source: curated
    value: "X-Test: safe"
  - id: sql-other
    category: sql-injection
    context: query
    risk: medium
    destructive: false
    max_attempts: 3
    source: curated
    payload: "' AND '1'='1"
`

func writeRegistry(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "payload-registry.yaml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func safeLimits() *policy.PolicyLimits {
	return &policy.PolicyLimits{MaxEntriesPerTask: 2, MaxRequestsTotal: 4, RateLimitRPS: 1, MaxConcurrency: 1, StopOn429: true, StopOnRepeated5xx: true, DestructivePayloads: "deny", ExfiltrationPayloads: "deny", CredentialAttackLists: "deny"}
}

func TestLoadAndSelectIsDeterministicAndBounded(t *testing.T) {
	r, err := Load(writeRegistry(t, registryFixture))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Select(Selection{Context: "query", Risk: risk.LevelMedium, MaxEntries: 10, Budget: 4}, safeLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "sql-basic" || got[1].ID != "sql-other" {
		t.Fatalf("selection = %#v", got)
	}
	if got2, _ := r.Select(Selection{Context: "query", Risk: risk.LevelMedium, MaxEntries: 10, Budget: 4}, safeLimits()); got2[0].ID != got[0].ID || got2[1].ID != got[1].ID {
		t.Fatal("selection must be deterministic")
	}
}

func TestLoadRejectsMalformedMetadataAndUnsafePayloads(t *testing.T) {
	cases := []string{
		"version: 1\npayloads:\n  - id: x\n    category: c\n    context: q\n    risk: low\n    destructive: false\n    max_attempts: 1\n    source: curated\n",
		"version: 1\npayloads:\n  - id: x\n    category: credential-attack\n    context: q\n    risk: critical\n    destructive: false\n    max_attempts: 1\n    source: curated\n    payload: password123\n",
		"version: 1\npayloads:\n  - id: x\n    category: c\n    context: q\n    risk: low\n    destructive: true\n    max_attempts: 1\n    source: curated\n    payload: safe\n",
	}
	for i, s := range cases {
		if _, err := Load(writeRegistry(t, s)); err == nil {
			t.Errorf("case %d should fail closed", i)
		}
	}
}

func TestSelectEnforcesBudgetAndPolicy(t *testing.T) {
	r, err := Load(writeRegistry(t, registryFixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Select(Selection{Context: "query", Risk: risk.LevelLow, MaxEntries: 2, Budget: 0}, safeLimits()); err == nil {
		t.Fatal("zero budget must be denied")
	}
	limited := safeLimits()
	limited.MaxEntriesPerTask = 1
	got, err := r.Select(Selection{Context: "query", Risk: risk.LevelMedium, MaxEntries: 10, Budget: 4}, limited)
	if err != nil || len(got) != 1 {
		t.Fatalf("bounded selection = %#v, %v", got, err)
	}
	limited.MaxRequestsTotal = 1
	if _, err := r.Select(Selection{Context: "query", Risk: risk.LevelMedium, MaxEntries: 2, Budget: 2}, limited); err == nil {
		t.Fatal("budget above policy must fail")
	}
}
