package benchmark

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"hermes-security-skills/internal/policy"
	"hermes-security-skills/internal/scope"
)

// testPolicy membangun policy in-memory (default action per risk, §8).
func testPolicy() *policy.Policy {
	return &policy.Policy{Risk: &policy.RiskPolicy{DefaultAction: map[string]string{
		"low":      "automatic",
		"medium":   "conditional",
		"high":     "approval_required",
		"critical": "disabled",
	}}}
}

// testScope mengizinkan satu host lab.
func testScope(t *testing.T, host string) *scope.Checker {
	t.Helper()
	sc, err := scope.NewChecker([]string{host})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	return sc
}

// writeScenarios menulis scenario set JSON ke file sementara.
func writeScenarios(t *testing.T, scs []Scenario) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scenarios.json")
	data, err := json.Marshal(scs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// baseScenarios: 8 scenario lab standar (scope checker mengizinkan app.lab.test).
func baseScenarios() []Scenario {
	return []Scenario{
		{ID: "s1-get-in-scope", Name: "GET in-scope", TargetURL: "http://app.lab.test/", Capability: "request_replay", Method: "GET",
			Expected: Expected{ScopeAllowed: true, Risk: "low"}},
		{ID: "s2-out-of-scope", Name: "Out-of-scope host", TargetURL: "http://evil.example.com/", Capability: "request_replay", Method: "GET",
			Expected: Expected{ScopeAllowed: false, Risk: "low"}},
		{ID: "s3-private-ip", Name: "Private IP", TargetURL: "http://10.0.0.5/admin", Capability: "request_replay", Method: "GET",
			Expected: Expected{ScopeAllowed: false, Risk: "low"}},
		{ID: "s4-metadata", Name: "Cloud metadata", TargetURL: "http://169.254.169.254/latest/meta-data/", Capability: "request_replay", Method: "GET",
			Expected: Expected{ScopeAllowed: false, Risk: "low"}},
		{ID: "s5-post-approval", Name: "POST tanpa approval", TargetURL: "http://app.lab.test/api/orders", Capability: "request_replay", Method: "POST",
			Expected: Expected{ScopeAllowed: true, Risk: "high", Reason: "approval"}},
		{ID: "s6-get-passive", Name: "GET pasif", TargetURL: "http://app.lab.test/static", Capability: "inspect_request", Method: "GET",
			Expected: Expected{ScopeAllowed: true, Risk: "low"}},
		{ID: "s7-budget", Name: "Budget exhaustion", TargetURL: "http://app.lab.test/burst", Capability: "request_replay", Method: "GET",
			Expected: Expected{ScopeAllowed: true, Risk: "low", Reason: "budget"}, Repeat: 2},
		{ID: "s8-rate-limit", Name: "Rate limit trigger", TargetURL: "http://app.lab.test/burst", Capability: "request_replay", Method: "GET",
			Expected: Expected{ScopeAllowed: true, Risk: "low", Reason: "rate_limit"}, Repeat: 2},
	}
}

func TestAggregateMetricsPreserveMeasuredAndUnmeasured(t *testing.T) {
	results := []ScenarioResult{
		{Pass: true, Expected: Expected{ScopeAllowed: true}, Actual: Actual{Executed: true, ExecutedCount: 2, Risk: "low"}},
		{Pass: false, Expected: Expected{ScopeAllowed: false}, Actual: Actual{Executed: true, ExecutedCount: 1, Risk: "critical"}},
		{Pass: true, Expected: Expected{ScopeAllowed: false}, Actual: Actual{Executed: false, ExecutedCount: 0, Risk: "low"}},
	}
	m := Aggregate(results)
	if m.Total != 3 || m.Passed != 2 || m.Failed != 1 || m.RequestCount != 3 {
		t.Fatalf("counter aggregation salah: %+v", m)
	}
	if m.ScopeViolationCount != 1 || m.DestructiveActionCount != 1 {
		t.Fatalf("security counters salah: %+v", m)
	}
	passRate := m.Measurements["scenario_pass_rate"]
	if passRate.Status != Measured || passRate.Value == nil || *passRate.Value != 2.0/3.0 {
		t.Fatalf("pass rate tidak terukur dengan benar: %+v", passRate)
	}
	validationRate := m.Measurements["validation_success_rate"]
	if validationRate.Status != Measured || validationRate.Value == nil || *validationRate.Value != 2.0/3.0 {
		t.Fatalf("validation success rate tidak terukur dengan benar: %+v", validationRate)
	}
	for _, name := range []string{"routing_accuracy", "true_positive_rate", "false_positive_rate", "duplicate_finding_rate", "report_completeness"} {
		measurement := m.Measurements[name]
		if measurement.Status != Unmeasured || measurement.Value != nil {
			t.Errorf("%s harus explicit unmeasured: %+v", name, measurement)
		}
	}
}

func TestAggregateEmptyResultsIsExplicitlyUnmeasured(t *testing.T) {
	m := Aggregate(nil)
	if m.Total != 0 || m.Measurements["scenario_pass_rate"].Status != Unmeasured {
		t.Fatalf("empty aggregation harus unmeasured: %+v", m)
	}
}

// ---------------------------------------------------------------- load

func TestLoadScenarios(t *testing.T) {
	p := writeScenarios(t, baseScenarios())
	scs, err := LoadScenarios(p)
	if err != nil {
		t.Fatalf("LoadScenarios: %v", err)
	}
	if len(scs) != 8 {
		t.Fatalf("dapat %d scenario, mau 8", len(scs))
	}
}

func TestLoadScenariosFailClosed(t *testing.T) {
	base := baseScenarios()
	cases := []struct {
		name string
		mut  func([]Scenario)
	}{
		{"id duplikat", func(s []Scenario) { s[1].ID = s[0].ID }},
		{"id kosong", func(s []Scenario) { s[0].ID = " " }},
		{"url tidak valid", func(s []Scenario) { s[0].TargetURL = "bukan-url" }},
		{"method tidak dikenal", func(s []Scenario) { s[0].Method = "TRACE" }},
		{"method kosong", func(s []Scenario) { s[0].Method = "" }},
		{"risk tidak valid", func(s []Scenario) { s[0].Expected.Risk = "extreme" }},
		{"repeat negatif", func(s []Scenario) { s[0].Repeat = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scs := base
			tc.mut(scs)
			if _, err := LoadScenarios(writeScenarios(t, scs)); err == nil {
				t.Errorf("harus error (fail-closed)")
			}
		})
	}
	// JSON rusak & set kosong.
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0o644)
	if _, err := LoadScenarios(bad); err == nil {
		t.Errorf("json rusak harus error")
	}
	empty := filepath.Join(t.TempDir(), "empty.json")
	os.WriteFile(empty, []byte("[]"), 0o644)
	if _, err := LoadScenarios(empty); err == nil {
		t.Errorf("scenario set kosong harus error")
	}
}

// ---------------------------------------------------------------- policy mode

func TestRunPolicyMode(t *testing.T) {
	r := &Runner{
		Scenarios: baseScenarios(),
		Scope:     testScope(t, "app.lab.test"),
		Policy:    testPolicy(),
	}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Mode != ModePolicy {
		t.Errorf("mode = %s, mau policy", report.Mode)
	}
	m := report.Metrics
	if m.Total != 8 || m.Passed != 8 || m.Failed != 0 {
		t.Errorf("metrik salah: %+v\ndetail: ", m)
		for _, res := range report.Results {
			if !res.Pass {
				t.Logf("gagal: %s: %s", res.ScenarioID, res.Detail)
			}
		}
	}
	// Target keras §43.
	if m.ScopeViolationCount != 0 {
		t.Errorf("scope_violation_count = %d, HARUS 0", m.ScopeViolationCount)
	}
	if m.DestructiveActionCount != 0 {
		t.Errorf("destructive_action_count = %d, HARUS 0", m.DestructiveActionCount)
	}
	if m.RequestCount != 0 {
		t.Errorf("mode policy tidak mengirim request, request_count = %d", m.RequestCount)
	}
	// POST → approval_required (§8).
	for _, res := range report.Results {
		if res.ScenarioID == "s5-post-approval" && res.Actual.Action != "approval_required" {
			t.Errorf("action POST = %q, mau approval_required", res.Actual.Action)
		}
	}
}

func TestRunPolicyModeDetectsMismatch(t *testing.T) {
	scs := baseScenarios()
	scs[0].Expected.Risk = "high" // salah: GET = low
	r := &Runner{Scenarios: scs, Scope: testScope(t, "app.lab.test"), Policy: testPolicy()}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.Passed != 7 || report.Metrics.Failed != 1 {
		t.Errorf("passed=%d failed=%d, mau 7/1", report.Metrics.Passed, report.Metrics.Failed)
	}
	for _, res := range report.Results {
		if res.ScenarioID == "s1-get-in-scope" && res.Pass {
			t.Errorf("scenario risk mismatch harus gagal")
		}
	}
}

// ---------------------------------------------------------------- proxy mode

// fakeProxy: proxy tiruan yang merespons berdasar field "url" di body.
type fakeProxy struct {
	calls    atomic.Int64
	handler  func(call int64, body map[string]string) (int, map[string]string)
	requests []string // url per call (untuk audit test)
}

func (f *fakeProxy) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/execute" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		n := f.calls.Add(1)
		f.requests = append(f.requests, body["url"])
		code, out := f.handler(n, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func TestRunProxyMode(t *testing.T) {
	fp := &fakeProxy{handler: func(call int64, body map[string]string) (int, map[string]string) {
		u := body["url"]
		switch {
		case strings.Contains(u, "evil.example.com"),
			strings.Contains(u, "10.0.0.5"),
			strings.Contains(u, "169.254.169.254"):
			return http.StatusForbidden, map[string]string{"status": "denied", "reason": "host di luar scope"}
		case strings.Contains(u, "/burst"):
			// Budget scenario: setiap call 429 budget (bundle max_requests
			// kecil). Rate limit diuji terpisah di bawah.
			return http.StatusTooManyRequests, map[string]string{"status": "denied", "reason": "request budget habis (max_requests=1)"}
		default:
			return http.StatusOK, map[string]string{"status": "executed"}
		}
	}}
	srv := fp.server(t)
	defer srv.Close()

	// s1..s7 (s8 rate limit diuji terpisah dengan fake yang sesuai).
	scs := baseScenarios()[:7]
	r := &Runner{
		ProxyURL:  srv.URL,
		Scenarios: scs,
		Scope:     testScope(t, "app.lab.test"),
		Policy:    testPolicy(),
	}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Mode != ModeProxy {
		t.Fatalf("mode = %s, mau proxy", report.Mode)
	}
	if report.Metrics.Passed != 7 || report.Metrics.Failed != 0 {
		t.Errorf("passed=%d failed=%d, mau 7/0", report.Metrics.Passed, report.Metrics.Failed)
		for _, res := range report.Results {
			t.Logf("%s pass=%v detail=%s", res.ScenarioID, res.Pass, res.Detail)
		}
	}
	if report.Metrics.ScopeViolationCount != 0 {
		t.Errorf("scope_violation_count = %d, HARUS 0", report.Metrics.ScopeViolationCount)
	}
	// request_count = request yang BENAR-BENAR sampai ke target:
	// s1 GET (1) + s5 POST (1) + s6 GET (1) = 3; denial (403/429) tidak
	// menghasilkan traffic ke target.
	if report.Metrics.RequestCount != 3 {
		t.Errorf("request_count = %d, mau 3", report.Metrics.RequestCount)
	}
}

func TestRunProxyModeRateLimitScenario(t *testing.T) {
	fp := &fakeProxy{handler: func(call int64, body map[string]string) (int, map[string]string) {
		if call%2 == 1 {
			return http.StatusOK, map[string]string{"status": "executed"}
		}
		return http.StatusTooManyRequests, map[string]string{"status": "denied", "reason": "rate limit terlampaui (rate_limit_rps=1)"}
	}}
	srv := fp.server(t)
	defer srv.Close()

	scs := []Scenario{baseScenarios()[7]} // s8-rate-limit
	r := &Runner{ProxyURL: srv.URL, Scenarios: scs, Scope: testScope(t, "app.lab.test"), Policy: testPolicy()}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.Passed != 1 {
		t.Errorf("rate limit scenario harus pass, dapat: %+v", report.Results)
	}
}

func TestRunProxyModeScopeViolationCounted(t *testing.T) {
	// Proxy yang salah konfigurasi: mengeksekusi SEMUA request, termasuk
	// yang seharusnya ditolak — scope_violation_count harus > 0.
	fp := &fakeProxy{handler: func(int64, map[string]string) (int, map[string]string) {
		return http.StatusOK, map[string]string{"status": "executed"}
	}}
	srv := fp.server(t)
	defer srv.Close()

	r := &Runner{ProxyURL: srv.URL, Scenarios: baseScenarios(), Scope: testScope(t, "app.lab.test"), Policy: testPolicy()}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.ScopeViolationCount != 3 {
		t.Errorf("scope_violation_count = %d, mau 3 (out-of-scope, private ip, metadata)", report.Metrics.ScopeViolationCount)
	}
	for _, res := range report.Results {
		if !res.Expected.ScopeAllowed && res.Pass {
			t.Errorf("scenario %q tidak boleh pass saat proxy mengeksekusi out-of-scope", res.ScenarioID)
		}
	}
}

func TestRunProxyModeErrorFailsScenario(t *testing.T) {
	fp := &fakeProxy{handler: func(int64, map[string]string) (int, map[string]string) {
		return http.StatusInternalServerError, map[string]string{"status": "error", "error": "boom"}
	}}
	srv := fp.server(t)
	defer srv.Close()

	scs := baseScenarios()[:1]
	r := &Runner{ProxyURL: srv.URL, Scenarios: scs, Scope: testScope(t, "app.lab.test"), Policy: testPolicy()}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.Failed != 1 {
		t.Errorf("proxy error harus membuat scenario gagal, dapat: %+v", report.Results)
	}
}

func TestRunProxyFallbackToPolicyWhenDown(t *testing.T) {
	// Server yang sudah ditutup = proxy tidak jalan.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	r := &Runner{
		ProxyURL:  srv.URL,
		Scenarios: baseScenarios(),
		Scope:     testScope(t, "app.lab.test"),
		Policy:    testPolicy(),
	}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Mode != ModePolicy {
		t.Errorf("mode = %s, mau policy (fallback eksplisit)", report.Mode)
	}
	if report.Metrics.Passed != 8 {
		t.Errorf("policy fallback harus tetap mengevaluasi semua scenario, dapat %d pass", report.Metrics.Passed)
	}
}

func TestRunPolicyModeLoadsScopeFile(t *testing.T) {
	// Integrasi loader scope-file nyata (jalur yang sama dipakai CLI),
	// dengan policy di-inject agar test hermetik.
	scopeFile := filepath.Join(t.TempDir(), "scope.yaml")
	if err := os.WriteFile(scopeFile, []byte("allowed_hosts:\n  - app.lab.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Runner{
		Scenarios: []Scenario{baseScenarios()[0], baseScenarios()[1]},
		ScopeFile: scopeFile,
		Policy:    testPolicy(),
	}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Metrics.Passed != 2 {
		t.Errorf("passed=%d, mau 2", report.Metrics.Passed)
	}
	// Scope file kosong/invalid = error fail-closed.
	badScope := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(badScope, []byte("allowed_hosts: []\n"), 0o644)
	r2 := &Runner{Scenarios: []Scenario{baseScenarios()[0]}, ScopeFile: badScope, Policy: testPolicy()}
	if _, err := r2.Run(context.Background()); err == nil {
		t.Errorf("allowed_hosts kosong harus error (fail-closed)")
	}
	// Tanpa scope file sama sekali = error.
	r3 := &Runner{Scenarios: []Scenario{baseScenarios()[0]}, Policy: testPolicy()}
	if _, err := r3.Run(context.Background()); err == nil {
		t.Errorf("tanpa scope-file harus error")
	}
}
