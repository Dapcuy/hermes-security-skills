// Package benchmark mengimplementasikan benchmark harness lab
// (ROADMAP §42 — Phase 11) dengan metrik kualitas & keamanan (§43).
//
// Dua mode eksekusi:
//
//	proxy  : setiap scenario dikirim ke control channel hermes-proxy
//	         (POST /execute) — policy dievaluasi in-line oleh proxy.
//	policy : proxy tidak jalan → evaluasi policy LOKAL (internal/scope +
//	         internal/risk + internal/policy). Tidak ada request yang
//	         dikirim ke target mana pun (request_count = 0).
//
// Metrik per run (§43):
//
//	total, passed, failed, scope_violation_count (target = 0),
//	destructive_action_count (target = 0), request_count.
//
// scope_violation_count = request yang BENAR-BENAR dieksekusi ke target
// padahal scenario mensyaratkan denial (expected.scope_allowed=false).
// destructive_action_count = request yang dieksekusi dengan klasifikasi
// risk CRITICAL (credential attack / exfiltration / persistence /
// lateral movement, §8) — kategori yang tidak boleh pernah dieksekusi.
//
// Fail-closed: scenarios.json tidak valid = error; proxy error per scenario
// = scenario gagal (bukan dianggap pass).
package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"hermes-security-skills/internal/policy"
	"hermes-security-skills/internal/risk"
	"hermes-security-skills/internal/scope"
	"hermes-security-skills/internal/yamlmini"
)

// Mode eksekusi benchmark.
const (
	ModePolicy = "policy" // evaluasi policy lokal, tanpa traffic ke target
	ModeProxy  = "proxy"  // via control channel hermes-proxy
)

// Expected hasil yang diharapkan dari sebuah scenario.
type Expected struct {
	ScopeAllowed bool   `json:"scope_allowed"`    // target harus diizinkan scope?
	Risk         string `json:"risk"`             // risk klasifikasi yang diharapkan (low|medium|high|critical)
	Reason       string `json:"reason,omitempty"` // hint opsional: "scope"|"budget"|"rate_limit"|"approval" (mode proxy)
}

// Scenario satu kasus uji lab (§42).
type Scenario struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	TargetURL  string   `json:"target_url"`
	Capability string   `json:"capability"`
	Method     string   `json:"method"`
	Expected   Expected `json:"expected"`
	// Repeat: jumlah pengiriman (default 1). Dipakai scenario budget/rate
	// limit yang butuh beberapa request untuk memicu stop condition.
	Repeat int `json:"repeat,omitempty"`
}

// Actual hasil aktual satu scenario.
type Actual struct {
	Executed      bool   `json:"executed"`                // minimal satu request sampai ke target?
	ExecutedCount int    `json:"executed_count"`          // jumlah request yang BENAR-BENAR sampai ke target
	ScopeAllowed  bool   `json:"scope_allowed"`           // hasil evaluasi scope
	Risk          string `json:"risk"`                    // klasifikasi risk aktual
	Action        string `json:"action,omitempty"`        // action policy (mode policy)
	HTTPStatuses  []int  `json:"http_statuses,omitempty"` // status respons proxy per pengiriman
	Reason        string `json:"reason,omitempty"`        // alasan denial / keterangan
}

// ScenarioResult hasil satu scenario.
type ScenarioResult struct {
	ScenarioID string   `json:"scenario_id"`
	Name       string   `json:"name"`
	Expected   Expected `json:"expected"`
	Actual     Actual   `json:"actual"`
	Pass       bool     `json:"pass"`
	Detail     string   `json:"detail,omitempty"` // penjelasan bila gagal
}

// MeasurementStatus menjelaskan apakah sebuah metrik benar-benar dapat
// dihitung dari data yang tersedia. "unmeasured" berbeda dari angka nol.
type MeasurementStatus string

const (
	Measured   MeasurementStatus = "measured"
	Unknown    MeasurementStatus = "unknown"
	Unmeasured MeasurementStatus = "unmeasured"
)

// Measurement adalah nilai metrik yang dapat dikonsumsi mesin tanpa
// menyamarkan metrik yang belum tersedia.
type Measurement struct {
	Status MeasurementStatus `json:"status"`
	Value  *float64          `json:"value"`
	Reason string            `json:"reason,omitempty"`
}

// Metrics agregasi metrik satu run (§43).
type Metrics struct {
	Total                  int `json:"total"`
	Passed                 int `json:"passed"`
	Failed                 int `json:"failed"`
	ScopeViolationCount    int `json:"scope_violation_count"`
	DestructiveActionCount int `json:"destructive_action_count"`
	RequestCount           int `json:"request_count"`
	// Measurements mencakup metrik roadmap yang tidak direpresentasikan oleh
	// counter legacy di atas, termasuk status unmeasured.
	Measurements map[string]Measurement `json:"measurements"`
}

func measured(value float64) Measurement {
	return Measurement{Status: Measured, Value: &value}
}

func unmeasured(reason string) Measurement {
	return Measurement{Status: Unmeasured, Reason: reason}
}

// Aggregate menghitung metrik yang memang dapat diturunkan dari hasil
// scenario. Ia tidak mengestimasi TP/FP atau routing accuracy tanpa ground
// truth; metrik tersebut dikembalikan sebagai unmeasured.
func Aggregate(results []ScenarioResult) Metrics {
	m := Metrics{Measurements: map[string]Measurement{}}
	for _, res := range results {
		m.Total++
		if res.Pass {
			m.Passed++
		} else {
			m.Failed++
		}
		if res.Actual.Executed && !res.Expected.ScopeAllowed {
			m.ScopeViolationCount++
		}
		if res.Actual.Executed && res.Actual.Risk == "critical" {
			m.DestructiveActionCount++
		}
		m.RequestCount += res.Actual.ExecutedCount
	}
	if m.Total > 0 {
		rate := measured(float64(m.Passed) / float64(m.Total))
		m.Measurements["scenario_pass_rate"] = rate
		m.Measurements["validation_success_rate"] = rate
	} else {
		m.Measurements["scenario_pass_rate"] = unmeasured("scenario results kosong")
		m.Measurements["validation_success_rate"] = unmeasured("scenario results kosong")
	}
	m.Measurements["request_count"] = measured(float64(m.RequestCount))
	m.Measurements["scope_violation_count"] = measured(float64(m.ScopeViolationCount))
	m.Measurements["destructive_action_count"] = measured(float64(m.DestructiveActionCount))
	for _, name := range []string{
		"routing_accuracy", "true_positive_rate", "false_positive_rate",
		"duplicate_finding_rate", "report_completeness", "token_usage",
		"timeout_frequency", "container_cleanup_success_rate", "tool_failure_rate",
		"policy_violation_count", "network_violation_count",
	} {
		m.Measurements[name] = unmeasured("requires ground truth or instrumentation not present in scenario results")
	}
	return m
}

// Report hasil lengkap satu benchmark run.
type Report struct {
	Mode      string           `json:"mode"`
	Timestamp string           `json:"timestamp"`
	ProxyURL  string           `json:"proxy_url,omitempty"`
	Metrics   Metrics          `json:"metrics"`
	Results   []ScenarioResult `json:"results"`
}

// Runner menjalankan scenario set terhadap proxy ATAU evaluasi policy lokal.
type Runner struct {
	// ProxyURL base control channel hermes-proxy (mis. http://127.0.0.1:8080).
	// Kosong = langsung mode policy. Bila diisi tapi proxy tidak merespons,
	// runner jatuh ke mode policy (dilaporkan di Report.Mode) — kegagalan
	// infrastruktur tidak pernah dihitung sebagai pass.
	ProxyURL string

	Scenarios []Scenario

	// Komponen policy untuk mode policy (wajib kecuali di test yang
	// menyuntikkan Scope/Policy langsung).
	ScopeFile   string // YAML {allowed_hosts}
	PolicyDir   string // direktori policy (risk.yaml, limits.yaml)
	RegistryDir string // opsional: validasi capability terdaftar

	// Injectables untuk test.
	Scope  *scope.Checker
	Policy *policy.Policy
	HTTP   *http.Client
	Now    func() time.Time
}

// LoadScenarios membaca dan memvalidasi file scenarios.json. Fail-closed:
// JSON tidak valid, id duplikat/kosong, URL/method/risk tidak valid = error.
func LoadScenarios(path string) ([]Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("benchmark: baca %s: %w", path, err)
	}
	var scs []Scenario
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&scs); err != nil {
		return nil, fmt.Errorf("benchmark: parse %s: %w", path, err)
	}
	if len(scs) == 0 {
		return nil, fmt.Errorf("benchmark: %s: scenario set kosong", path)
	}
	seen := map[string]bool{}
	for i := range scs {
		s := &scs[i]
		if strings.TrimSpace(s.ID) == "" {
			return nil, fmt.Errorf("benchmark: %s: scenario #%d tanpa id", path, i+1)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("benchmark: %s: id duplikat %q", path, s.ID)
		}
		seen[s.ID] = true
		u, err := url.Parse(strings.TrimSpace(s.TargetURL))
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("benchmark: %s: scenario %q target_url tidak valid", path, s.ID)
		}
		if s.Method == "" {
			return nil, fmt.Errorf("benchmark: %s: scenario %q tanpa method", path, s.ID)
		}
		switch strings.ToUpper(s.Method) {
		case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE":
		default:
			return nil, fmt.Errorf("benchmark: %s: scenario %q method %q tidak dikenal", path, s.ID, s.Method)
		}
		switch risk.Level(strings.ToLower(s.Expected.Risk)) {
		case risk.LevelLow, risk.LevelMedium, risk.LevelHigh, risk.LevelCritical:
		default:
			return nil, fmt.Errorf("benchmark: %s: scenario %q expected.risk %q tidak valid", path, s.ID, s.Expected.Risk)
		}
		if s.Repeat < 0 {
			return nil, fmt.Errorf("benchmark: %s: scenario %q repeat negatif", path, s.ID)
		}
	}
	return scs, nil
}

// Run menjalankan semua scenario dan mengembalikan Report. Error hanya
// untuk kegagalan fatal (policy lokal tidak bisa dimuat); kegagalan
// per-scenario masuk Report sebagai pass=false.
func (r *Runner) Run(ctx context.Context) (*Report, error) {
	if len(r.Scenarios) == 0 {
		return nil, fmt.Errorf("benchmark: tidak ada scenario")
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.HTTP == nil {
		r.HTTP = &http.Client{Timeout: 30 * time.Second}
	}

	// Policy lokal selalu dimuat — dipakai untuk klasifikasi risk/action
	// di kedua mode (metrik destructive & action dihitung konsisten).
	if r.Policy == nil {
		pol, err := policy.Load(r.PolicyDir)
		if err != nil {
			return nil, fmt.Errorf("benchmark: load policy: %w", err)
		}
		r.Policy = pol
	}
	if r.Scope == nil {
		sc, err := loadScopeChecker(r.ScopeFile)
		if err != nil {
			return nil, fmt.Errorf("benchmark: load scope: %w", err)
		}
		r.Scope = sc
	}

	mode := ModePolicy
	if strings.TrimSpace(r.ProxyURL) != "" {
		if proxyAlive(ctx, r.HTTP, r.ProxyURL) {
			mode = ModeProxy
		}
		// Proxy tidak jalan → mode policy (§ spec: fallback eksplisit,
		// dilaporkan di Report.Mode, bukan silent).
	}

	report := &Report{
		Mode:      mode,
		Timestamp: r.Now().UTC().Format(time.RFC3339),
		ProxyURL:  r.ProxyURL,
	}
	for _, sc := range r.Scenarios {
		res := r.runScenario(ctx, mode, sc)
		report.Results = append(report.Results, res)
	}
	report.Metrics = Aggregate(report.Results)
	return report, nil
}

// evaluatePolicy mengevaluasi scope + risk + action secara lokal untuk satu
// scenario (dipakai di kedua mode sebagai sumber kebenaran klasifikasi).
func (r *Runner) evaluatePolicy(sc Scenario) (scopeAllowed bool, lvl risk.Level, action risk.Action, reason string) {
	if err := r.Scope.Check(sc.TargetURL); err != nil {
		return false, risk.Classify(risk.Operation{Method: sc.Method}), "", err.Error()
	}
	lvl = risk.Classify(risk.Operation{Method: sc.Method})
	act, err := r.Policy.Evaluate(sc.Capability, lvl)
	if err != nil {
		// Capability tidak ada di default_action / risk kosong = fail-closed.
		return true, lvl, "", err.Error()
	}
	return true, lvl, act, ""
}

// runScenario mengeksekusi satu scenario sesuai mode.
func (r *Runner) runScenario(ctx context.Context, mode string, sc Scenario) ScenarioResult {
	res := ScenarioResult{ScenarioID: sc.ID, Name: sc.Name, Expected: sc.Expected}

	scopeOK, lvl, action, reason := r.evaluatePolicy(sc)
	res.Actual.ScopeAllowed = scopeOK
	res.Actual.Risk = string(lvl)
	res.Actual.Action = string(action)

	switch mode {
	case ModePolicy:
		res.Actual.Reason = reason
		if reason != "" && scopeOK {
			res.Actual.Action = "" // action tidak dapat ditentukan — fail-closed
		}
		// Pass = scope cocok DAN risk klasifikasi cocok. Action mengikuti
		// risk via default_action (mis. high → approval_required, §8).
		if scopeOK != sc.Expected.ScopeAllowed {
			if scopeOK {
				res.Detail = fmt.Sprintf("policy mengizinkan %s padahal diharapkan ditolak", sc.TargetURL)
			} else {
				res.Detail = "policy menolak padahal diharapkan diizinkan: " + reason
			}
			return res
		}
		if res.Actual.Risk != strings.ToLower(sc.Expected.Risk) {
			res.Detail = fmt.Sprintf("risk aktual %q != expected %q", res.Actual.Risk, sc.Expected.Risk)
			return res
		}
		res.Pass = true
		return res

	case ModeProxy:
		repeat := sc.Repeat
		if repeat <= 0 {
			repeat = 1
		}
		anyExecuted, anyBudget, anyRate, allExecuted := false, false, false, true
		for i := 0; i < repeat; i++ {
			executed, status, denyReason, err := r.executeViaProxy(ctx, sc)
			if err != nil {
				res.Detail = fmt.Sprintf("proxy error: %v", err)
				return res // kegagalan infrastruktur = gagal, bukan pass
			}
			res.Actual.HTTPStatuses = append(res.Actual.HTTPStatuses, status)
			if executed {
				anyExecuted = true
				res.Actual.ExecutedCount++
			} else {
				allExecuted = false
				if status == http.StatusTooManyRequests {
					switch {
					case strings.Contains(strings.ToLower(denyReason), "budget"):
						anyBudget = true
					case strings.Contains(strings.ToLower(denyReason), "rate limit"):
						anyRate = true
					}
				}
			}
			if i == 0 {
				res.Actual.Reason = denyReason
			}
		}
		res.Actual.Executed = anyExecuted

		// Pass criteria per mode proxy:
		//   - expected denied  → TIDAK BOLEH ada yang dieksekusi.
		//   - expected budget  → minimal satu 429 budget.
		//   - expected rate    → minimal satu 429 rate limit.
		//   - expected allowed → semua ter-eksekusi.
		switch {
		case !sc.Expected.ScopeAllowed:
			if anyExecuted {
				res.Detail = "VIOLASI SCOPE: request dieksekusi ke target yang diharapkan ditolak"
				return res
			}
		case sc.Expected.Reason == "budget":
			if !anyBudget {
				res.Detail = "budget tidak terpicu (tidak ada 429 budget) — cek repeat vs bundle max_requests"
				return res
			}
		case sc.Expected.Reason == "rate_limit":
			if !anyRate {
				res.Detail = "rate limit tidak terpicu (tidak ada 429 rate limit) — cek repeat vs bundle rate_limit_rps"
				return res
			}
		default:
			if !allExecuted {
				res.Detail = "diharapkan dieksekusi penuh, dapat denial: " + res.Actual.Reason
				return res
			}
		}
		res.Pass = true
		return res

	default:
		res.Detail = "mode tidak dikenal: " + mode
		return res
	}
}

// executeViaProxy mengirim satu POST /execute ke control channel proxy.
// Return: (executed, httpStatus, denialReason, error).
func (r *Runner) executeViaProxy(ctx context.Context, sc Scenario) (bool, int, string, error) {
	body, err := json.Marshal(map[string]string{
		"url":    sc.TargetURL,
		"method": sc.Method,
	})
	if err != nil {
		return false, 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(r.ProxyURL, "/")+"/execute", bytes.NewReader(body))
	if err != nil {
		return false, 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false, resp.StatusCode, "", fmt.Errorf("baca respons proxy: %w", err)
	}
	var out struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
		Error  string `json:"error"`
	}
	_ = json.Unmarshal(data, &out) // body non-JSON tetap dinilai dari status code
	switch resp.StatusCode {
	case http.StatusOK:
		return true, resp.StatusCode, "", nil
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusBadRequest, http.StatusMethodNotAllowed:
		return false, resp.StatusCode, out.Reason, nil
	default:
		return false, resp.StatusCode, out.Reason, fmt.Errorf("proxy status %d: %s%s", resp.StatusCode, out.Reason, out.Error)
	}
}

// proxyAlive mengecek control channel hidup dengan POST /execute kosong —
// respons APAPUN (termasuk 400) berarti proxy hidup; transport error berarti
// tidak jalan.
func proxyAlive(ctx context.Context, client *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/execute", strings.NewReader("{}"))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return true
}

// loadScopeChecker membangun scope.Checker dari file YAML {allowed_hosts}.
// (Duplikasi kecil loader commands.go — package ini tidak boleh bergantung
// pada package main.)
func loadScopeChecker(path string) (*scope.Checker, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("scope-file wajib diisi untuk mode policy")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baca %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	raw, ok := doc["allowed_hosts"]
	if !ok {
		return nil, fmt.Errorf("%s: field 'allowed_hosts' tidak ada", path)
	}
	seq, ok := raw.([]any)
	if !ok || len(seq) == 0 {
		return nil, fmt.Errorf("%s: 'allowed_hosts' harus seq tidak kosong", path)
	}
	hosts := make([]string, 0, len(seq))
	for _, v := range seq {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("%s: allowed_hosts harus berisi string", path)
		}
		hosts = append(hosts, s)
	}
	return scope.NewChecker(hosts)
}
