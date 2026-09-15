// Test tool kontrol (validate_scope / run_validator / abort_case) dan
// eksekusi capability provider "tool" (endpoint_discovery — ROADMAP v3.0
// §36) memakai fake docker exec helper — tanpa Docker sungguhan di unit
// test. E2E nyata dijalankan manual via scripts (lihat laporan verifikasi).
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/jobs"
	"hermes-security-skills/internal/payload"
	"hermes-security-skills/internal/risk"
	"hermes-security-skills/internal/toolregistry"
)

// fakeDocker: fake exec helper untuk dockerx.Execer — mengcover `version`,
// `image inspect`, `run` (dengan hook runFn untuk menulis output), `ps`,
// `rm`. Semua invocation terekam di invoked untuk assert baseline security.
type fakeDocker struct {
	mu      sync.Mutex
	invoked [][]string
	runFn   func(args []string) error // opsional: side-effect docker run
	failPs  bool
}

type acceptSignatureVerifier struct{}

func (acceptSignatureVerifier) Verify(context.Context, string) error { return nil }

func (f *fakeDocker) Exec(ctx context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invoked = append(f.invoked, args)
	if len(args) == 0 {
		return nil, fmt.Errorf("fakeDocker: tanpa argumen")
	}
	switch args[0] {
	case "version":
		return []byte(`{"Client":{"Version":"24.0"},"Server":{"Version":"24.0.7"}}`), nil
	case "image":
		if len(args) > 1 && args[1] == "inspect" {
			if len(args) >= 4 && strings.Contains(args[3], "RepoDigests") {
				return []byte(fmt.Sprintf(`["%s"]`, args[len(args)-1])), nil
			}
			return []byte("fake-image-id\n"), nil
		}
	case "run":
		if f.runFn != nil {
			if err := f.runFn(args); err != nil {
				return []byte("fake run error: " + err.Error()), err
			}
		}
		return []byte("fake container output"), nil
	case "ps":
		if f.failPs {
			return nil, fmt.Errorf("fakeDocker: ps gagal")
		}
		return []byte("abc123def\n"), nil
	case "rm":
		return []byte("abc123def\n"), nil
	}
	return []byte(""), nil
}

func (f *fakeDocker) runs() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, 0, len(f.invoked))
	for _, args := range f.invoked {
		if args[0] == "run" {
			out = append(out, args)
		}
	}
	return out
}

// runArgsFlat menggabungkan satu invocation `docker run ...` menjadi satu
// string untuk assert substring.
func runArgsFlat(args []string) string { return strings.Join(args, " ") }

// mountOf mengambil sumber bind mount untuk dest container (mis.
// /workspace/output) dari argumen `docker run`. Source path Windows
// mengandung ":" (drive letter) — match dari suffix container path.
func mountOf(args []string, dest string) (string, bool) {
	for i, a := range args {
		if a != "-v" || i+1 >= len(args) {
			continue
		}
		m := args[i+1]
		for _, suffix := range []string{dest + ":ro", ":" + dest} {
			if strings.HasSuffix(m, suffix) {
				return strings.TrimSuffix(m, suffix), true
			}
		}
	}
	return "", false
}

// writeFakeToolResult: hook runFn yang menulis validation-result.json ke
// output dir hasil mount (simulasi wrapper §33/§39).
func writeFakeToolResult(observations ...map[string]any) func(args []string) error {
	return func(args []string) error {
		outDir, ok := mountOf(args, dockerxOutputDir)
		if !ok {
			return fmt.Errorf("fakeDocker: mount output tidak ditemukan")
		}
		result := map[string]any{
			"task_id":      "fake-task",
			"validator":    map[string]any{"id": "tool-fake", "version": "0.1.0"},
			"status":       "observed",
			"observations": observations,
			"provenance":   map[string]any{"tool": "fake", "tool_version": "v0.0.0"},
		}
		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(outDir, "validation-result.json"), data, 0o600)
	}
}

const (
	dockerxOutputDir   = "/workspace/output"
	dockerxInputDirArg = "/workspace/input/bundle.json"
)

// toolServer: server dengan endpoint_discovery + template_based_validation
// di capability registry, Tool Registry fixture, dan fake docker.
func toolServer(t *testing.T, mutate func(*Config)) (*Server, *approval.Store, *fakeDocker) {
	t.Helper()
	fd := &fakeDocker{}
	srv, store := newTestServer(t, map[string]any{
		"endpoint_discovery": map[string]any{
			"risk": "medium", "default_provider": "tool",
			"requires_scope": true, "requires_network": true,
		},
		"template_based_validation": map[string]any{
			"risk": "medium", "default_provider": "tool",
			"requires_scope": true, "requires_network": true,
		},
	}, func(c *Config) {
		c.ToolRegistry = testToolRegistry(t)
		c.Docker = fd
		c.SignatureVerifier = acceptSignatureVerifier{}
		// Scope lab: target lokal yang dipakai tool wrapper (bundle + scope
		// file memakai entry yang sama — wrapper cocok exact host:port).
		c.Scope = mustChecker(t, []string{"host.docker.internal:9090", "host.docker.internal"})
		if mutate != nil {
			mutate(c)
		}
	})
	return srv, store, fd
}

// ------------------------------------------------------------- validate_scope

func TestToolsCallValidateScope(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	// In-scope → allowed, tanpa traffic.
	resps := runServer(t, srv, mustRequest(t, 40, "tools/call", map[string]any{
		"name":      "security.validate_scope",
		"arguments": map[string]any{"url": "http://localhost:8901/orders/1"},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("validate_scope in-scope harus allowed: %v", resps[0])
	}
	if txt := callText(t, resps[0]); !strings.Contains(txt, `"status":"allowed"`) {
		t.Errorf("status harus allowed: %s", txt)
	}
	// Out-of-scope → denied + reason, TETAP tanpa traffic.
	resps = runServer(t, srv, mustRequest(t, 41, "tools/call", map[string]any{
		"name":      "security.validate_scope",
		"arguments": map[string]any{"url": "http://evil.example.com/"},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true {
		t.Fatalf("validate_scope out-of-scope harus denied: %v", resps[0])
	}
	if txt := callText(t, resps[0]); !strings.Contains(txt, `"status":"denied"`) || !strings.Contains(txt, "scope") {
		t.Errorf("denial harus dari scope check: %s", txt)
	}
	// Fail-closed: tanpa scope rules = denied (bukan allow).
	srv2, _ := newTestServer(t, nil, func(c *Config) { c.Scope = nil; c.ScopeFile = "" })
	resps = runServer(t, srv2, mustRequest(t, 42, "tools/call", map[string]any{
		"name":      "security.validate_scope",
		"arguments": map[string]any{"url": "http://localhost:8901/"},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "fail-closed") {
		t.Errorf("tanpa scope rules harus denied fail-closed: %v", resps[0])
	}
	// Argument hilang → -32602.
	resps = runServer(t, srv, mustRequest(t, 43, "tools/call", map[string]any{
		"name": "security.validate_scope", "arguments": map[string]any{},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("url hilang harus -32602, dapat %v", resps[0])
	}
}

// --------------------------------------------------------------- run_validator

// writeManifestFixture membuat image manifest fixture (§21) berisi satu
// image json-diff dan mengembalikan path-nya.
func writeManifestFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image-manifest.yaml")
	content := `registry: ghcr.io/test
images:
  - name: hermes-validator-json
    tag: 0.1.0
    network: none
    egress: false
    digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestToolsCallRunValidatorRegistered(t *testing.T) {
	fd := &fakeDocker{runFn: writeFakeToolResult(map[string]any{"type": "json_diff", "detail": "$.a: 1 -> 2"})}
	manifest := writeManifestFixture(t)
	srv, _ := newTestServer(t, map[string]any{}, func(c *Config) {
		c.ManifestPath = manifest
		c.Docker = fd
		c.SignatureVerifier = acceptSignatureVerifier{}
	})
	resps := runServer(t, srv, mustRequest(t, 50, "tools/call", map[string]any{
		"name": "security.run_validator",
		"arguments": map[string]any{
			"validator_id": "json-diff",
			"task": map[string]any{
				"task_id":   "task-rv-1",
				"validator": map[string]any{"id": "json-diff"},
				"payload":   map[string]any{"json_a": map[string]any{"a": 1}, "json_b": map[string]any{"a": 2}},
			},
			"case": "case-rv",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("run_validator validator terdaftar harus observed: %v", resps[0])
	}
	var body struct {
		Status    string         `json:"status"`
		Provider  string         `json:"provider"`
		Validator string         `json:"validator"`
		Image     string         `json:"image"`
		Case      string         `json:"case"`
		Result    map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(callText(t, resps[0])), &body); err != nil {
		t.Fatalf("payload bukan JSON: %v", err)
	}
	if body.Status != "observed" || body.Provider != "docker" || body.Validator != "json-diff" ||
		body.Image != "ghcr.io/test/hermes-validator-json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || body.Case != "case-rv" {
		t.Errorf("payload salah: %+v", body)
	}
	if len(body.Result) == 0 || body.Result["status"] != "observed" {
		t.Errorf("result harus diteruskan: %+v", body.Result)
	}
	// Baseline: container network=none + label case.
	runs := fd.runs()
	if len(runs) != 1 {
		t.Fatalf("mau 1 docker run, dapat %d", len(runs))
	}
	flat := runArgsFlat(runs[0])
	for _, want := range []string{"--network none", "--read-only", "--cap-drop ALL", "hermes.case=case-rv"} {
		if !strings.Contains(flat, want) {
			t.Errorf("docker run args kurang %q: %s", want, flat)
		}
	}
	if strings.Contains(flat, "--network bridge") {
		t.Errorf("validator WAJIB network none (§16): %s", flat)
	}
}

func TestToolsCallRunValidatorFailClosed(t *testing.T) {
	manifest := writeManifestFixture(t)
	srv, _ := newTestServer(t, nil, func(c *Config) { c.ManifestPath = manifest; c.Docker = &fakeDocker{} })
	// (1) Validator tidak terdaftar di manifest → denied.
	resps := runServer(t, srv, mustRequest(t, 51, "tools/call", map[string]any{
		"name": "security.run_validator",
		"arguments": map[string]any{
			"validator_id": "sqlmap-scan",
			"task":         map[string]any{"task_id": "t", "validator": map[string]any{"id": "sqlmap-scan"}},
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "terdaftar") {
		t.Errorf("validator tidak terdaftar harus denied: %v", resps[0])
	}
	// (2) task.validator.id mismatch → -32602.
	resps = runServer(t, srv, mustRequest(t, 52, "tools/call", map[string]any{
		"name": "security.run_validator",
		"arguments": map[string]any{
			"validator_id": "json-diff",
			"task":         map[string]any{"task_id": "t", "validator": map[string]any{"id": "openapi-analysis"}},
		},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("validator.id mismatch harus -32602, dapat %v", resps[0])
	}
	// (3) Case aborted → denied (kill switch §10).
	jobsRoot := t.TempDir()
	if _, err := jobs.MarkAborted(jobsRoot, "case-dead"); err != nil {
		t.Fatal(err)
	}
	srv3, _ := newTestServer(t, nil, func(c *Config) { c.ManifestPath = manifest; c.Docker = &fakeDocker{}; c.JobsDir = jobsRoot })
	resps = runServer(t, srv3, mustRequest(t, 53, "tools/call", map[string]any{
		"name": "security.run_validator",
		"arguments": map[string]any{
			"validator_id": "json-diff",
			"task":         map[string]any{"task_id": "t", "validator": map[string]any{"id": "json-diff"}},
			"case":         "case-dead",
		},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "abort") {
		t.Errorf("case aborted harus denied: %v", resps[0])
	}
	// (4) Manifest tidak dikonfigurasi → denied fail-closed.
	srv4, _ := newTestServer(t, nil, func(c *Config) { c.ManifestPath = "" })
	resps = runServer(t, srv4, mustRequest(t, 54, "tools/call", map[string]any{
		"name": "security.run_validator",
		"arguments": map[string]any{
			"validator_id": "json-diff",
			"task":         map[string]any{"task_id": "t", "validator": map[string]any{"id": "json-diff"}},
		},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "fail-closed") {
		t.Errorf("tanpa manifest harus denied fail-closed: %v", resps[0])
	}
}

// ------------------------------------------------------------------ abort_case

func TestToolsCallAbortCase(t *testing.T) {
	fd := &fakeDocker{}
	jobsRoot := t.TempDir()
	srv, store := newTestServer(t, nil, func(c *Config) { c.JobsDir = jobsRoot; c.Docker = fd })
	// Seed satu approval aktif untuk case.
	if err := store.Save(approval.Record{
		CaseID: "case-kill", Capability: "request_replay", Host: "localhost",
		Method: "GET", Path: approval.PathAny, MaxRequests: 5,
		ExpiresAt: time.Now().Add(time.Hour).UTC(), Risk: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	resps := runServer(t, srv, mustRequest(t, 60, "tools/call", map[string]any{
		"name":      "security.abort_case",
		"arguments": map[string]any{"case": "case-kill"},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("abort_case harus sukses: %v", resps[0])
	}
	var body struct {
		Status           string `json:"status"`
		Case             string `json:"case"`
		ContainersKilled int    `json:"containers_killed"`
		ApprovalsRevoked int    `json:"approvals_revoked"`
	}
	if err := json.Unmarshal([]byte(callText(t, resps[0])), &body); err != nil {
		t.Fatalf("payload bukan JSON: %v", err)
	}
	if body.Status != "aborted" || body.Case != "case-kill" || body.ContainersKilled != 1 || body.ApprovalsRevoked != 1 {
		t.Errorf("payload abort salah: %+v", body)
	}
	// Marker ABORTED tertulis (task baru untuk case ini ditolak).
	if _, err := os.Stat(filepath.Join(jobsRoot, "case-kill", "ABORTED")); err != nil {
		t.Errorf("marker ABORTED tidak ada: %v", err)
	}
	// Setelah abort: request_replay pada case yang sama ditolak kill switch.
	resps = runServer(t, srv, mustRequest(t, 61, "tools/call", map[string]any{
		"name": "security.request_replay",
		"arguments": map[string]any{
			"url": "http://localhost:8901/", "method": "GET", "case": "case-kill",
		},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "abort") {
		t.Errorf("eksekusi setelah abort harus ditolak: %v", resps[0])
	}
	// Case id hilang → -32602.
	resps = runServer(t, srv, mustRequest(t, 62, "tools/call", map[string]any{
		"name": "security.abort_case", "arguments": map[string]any{},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("case hilang harus -32602, dapat %v", resps[0])
	}
}

// ------------------------------------------------------------ endpoint_discovery

func TestToolsCallEndpointDiscoveryHTTPX(t *testing.T) {
	srv, store, fd := toolServer(t, nil)
	fd.runFn = writeFakeToolResult(
		map[string]any{"type": "probe", "detail": "http://host.docker.internal:9090/ [200] [Demo] [Python]"},
	)
	resps := runServer(t, srv, mustRequest(t, 70, "tools/call", map[string]any{
		"name": "security.endpoint_discovery",
		"arguments": map[string]any{
			"tool":   "httpx",
			"target": "http://host.docker.internal:9090/",
			"case":   "case-disc",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("httpx automatic harus observed: %v", resps[0])
	}
	var body struct {
		Status   string         `json:"status"`
		Provider string         `json:"provider"`
		Tool     string         `json:"tool"`
		Image    string         `json:"image"`
		Result   map[string]any `json:"result"`
		JobDir   string         `json:"job_dir"`
	}
	if err := json.Unmarshal([]byte(callText(t, resps[0])), &body); err != nil {
		t.Fatalf("payload bukan JSON: %v", err)
	}
	if body.Status != "observed" || body.Provider != "tool" || body.Tool != "httpx" {
		t.Errorf("payload salah: %+v", body)
	}
	// Image ref = digest pin dari Tool Registry (§40).
	if body.Image != "hermes-tool-httpx@sha256:6e8e333d2ea9a91ae270f3d7a0bff4a86a653b7fab37b57270ea9526af1f19ae" {
		t.Errorf("image ref salah: %s", body.Image)
	}
	if len(body.Result) == 0 || body.Result["status"] != "observed" {
		t.Errorf("validation-result harus diteruskan: %+v", body.Result)
	}
	// docker run: baseline §15 + network bridge (tool wrapper) + env bundle
	// + argumen whitelist (-u target) + mount input/output.
	runs := fd.runs()
	if len(runs) != 1 {
		t.Fatalf("mau 1 docker run, dapat %d", len(runs))
	}
	flat := runArgsFlat(runs[0])
	for _, want := range []string{
		"--network bridge", "--read-only", "--cap-drop ALL",
		"POLICY_BUNDLE_SHA256=", "-e", dockerxInputDirArg,
		"-u http://host.docker.internal:9090/", "hermes.case=case-disc",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("docker run args kurang %q: %s", want, flat)
		}
	}
	// Tidak ada approval yang dibutuhkan/dikonsumsi untuk tool automatic.
	recs, _ := store.Load()
	if len(recs) != 0 {
		t.Errorf("tool automatic tidak boleh menyentuh approval store: %+v", recs)
	}
	// Workspace job dibuat di jobs dir.
	if _, err := os.Stat(body.JobDir); err != nil {
		t.Errorf("job dir tidak ada: %v", err)
	}
}

func TestToolsCallEndpointDiscoverySubfinder(t *testing.T) {
	srv, _, fd := toolServer(t, nil)
	fd.runFn = writeFakeToolResult(
		map[string]any{"type": "subdomain", "detail": "api.host.docker.internal"},
	)
	// Tanpa arg 'tool' pun boleh untuk capability dengan TEPAT satu tool —
	// endpoint_discovery punya 4, jadi tanpa tool = -32602.
	resps := runServer(t, srv, mustRequest(t, 71, "tools/call", map[string]any{
		"name": "security.endpoint_discovery", "arguments": map[string]any{"domain": "host.docker.internal"},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("endpoint_discovery multi-tool tanpa 'tool' harus -32602, dapat %v", resps[0])
	}
	// subfinder automatic — tanpa 'case' pun jalan (case default).
	resps = runServer(t, srv, mustRequest(t, 72, "tools/call", map[string]any{
		"name":      "security.endpoint_discovery",
		"arguments": map[string]any{"tool": "subfinder", "domain": "host.docker.internal"},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("subfinder automatic harus observed: %v", resps[0])
	}
	var body struct {
		Tool string `json:"tool"`
		Case string `json:"case"`
	}
	if err := json.Unmarshal([]byte(callText(t, resps[0])), &body); err != nil {
		t.Fatal(err)
	}
	if body.Tool != "subfinder" || body.Case != "mcp-default" {
		t.Errorf("subfinder payload salah: %+v", body)
	}
	runs := fd.runs()
	if len(runs) != 1 || !strings.Contains(runArgsFlat(runs[0]), "-d host.docker.internal") {
		t.Errorf("argumen subfinder salah: %v", runs)
	}
}

func TestToolsCallEndpointDiscoveryNmapDeniedWithoutApproval(t *testing.T) {
	srv, _, fd := toolServer(t, nil)
	resps := runServer(t, srv, mustRequest(t, 73, "tools/call", map[string]any{
		"name": "security.endpoint_discovery",
		"arguments": map[string]any{
			"tool":   "nmap",
			"target": "host.docker.internal:9090",
			"ports":  "1-1000",
			"case":   "case-nmap",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true {
		t.Fatalf("nmap tanpa approval harus denied: %v", resps[0])
	}
	txt := callText(t, resps[0])
	if !strings.Contains(txt, "denied") || !strings.Contains(txt, "approval") || !strings.Contains(txt, "nmap") {
		t.Errorf("denial harus menyebut denied+approval+nmap: %s", txt)
	}
	// TIDAK ada docker run — denial terjadi sebelum provider.
	if len(fd.runs()) != 0 {
		t.Errorf("nmap denied tidak boleh mengeksekusi container: %v", fd.runs())
	}
}

func TestToolsCallEndpointDiscoveryConditionalRequiresApproval(t *testing.T) {
	srv, store, fd := toolServer(t, nil)
	// ffuf (conditional) tanpa approval → denied.
	resps := runServer(t, srv, mustRequest(t, 74, "tools/call", map[string]any{
		"name": "security.endpoint_discovery",
		"arguments": map[string]any{
			"tool": "ffuf", "target": "http://host.docker.internal:9090/FUZZ",
			"wordlist": "/wordlists/small.txt", "case": "case-ffuf",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "approval") {
		t.Errorf("ffuf tanpa approval harus denied: %v", resps[0])
	}
	if len(fd.runs()) != 0 {
		t.Errorf("ffuf denied tidak boleh mengeksekusi container")
	}
	// Dengan scoped approval → observed, budget terkonsumsi.
	if err := store.Save(approval.Record{
		CaseID: "case-ffuf", Capability: "endpoint_discovery", Host: "host.docker.internal",
		Method: "GET", Path: approval.PathAny, MaxRequests: 5,
		ExpiresAt: time.Now().Add(time.Hour).UTC(), Risk: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	fd.runFn = writeFakeToolResult(map[string]any{"type": "fuzz", "detail": "/admin [302]"})
	resps = runServer(t, srv, mustRequest(t, 75, "tools/call", map[string]any{
		"name": "security.endpoint_discovery",
		"arguments": map[string]any{
			"tool": "ffuf", "target": "http://host.docker.internal:9090/FUZZ",
			"wordlist": "/wordlists/small.txt", "case": "case-ffuf",
		},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("ffuf dengan approval harus observed: %v", resps[0])
	}
	recs, _ := store.Load()
	if len(recs) != 1 || recs[0].Used != 1 {
		t.Errorf("budget approval harus terkonsumsi: %+v", recs)
	}
}

func TestToolsCallEndpointDiscoveryFailClosed(t *testing.T) {
	// (1) Tool Registry tidak dikonfigurasi → denied.
	srv, _, _ := toolServer(t, func(c *Config) { c.ToolRegistry = nil })
	resps := runServer(t, srv, mustRequest(t, 76, "tools/call", map[string]any{
		"name":      "security.endpoint_discovery",
		"arguments": map[string]any{"tool": "httpx", "target": "http://host.docker.internal:9090/"},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "Tool Registry") {
		t.Errorf("tanpa Tool Registry harus denied fail-closed: %v", resps[0])
	}
	// (2) Tool tidak dikenal → denied.
	srv2, _, _ := toolServer(t, nil)
	resps = runServer(t, srv2, mustRequest(t, 77, "tools/call", map[string]any{
		"name":      "security.endpoint_discovery",
		"arguments": map[string]any{"tool": "sqlmap", "target": "http://host.docker.internal:9090/"},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true {
		t.Errorf("tool tidak dikenal harus denied: %v", resps[0])
	}
	// (3) Target di luar scope → denied sebelum provider.
	srv3, _, fd3 := toolServer(t, nil)
	resps = runServer(t, srv3, mustRequest(t, 78, "tools/call", map[string]any{
		"name":      "security.endpoint_discovery",
		"arguments": map[string]any{"tool": "httpx", "target": "http://evil.example.com/"},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "scope") {
		t.Errorf("target out-of-scope harus denied oleh scope check: %v", resps[0])
	}
	if len(fd3.runs()) != 0 {
		t.Errorf("out-of-scope tidak boleh mengeksekusi container")
	}
	// (4) Tool milik capability lain ditolak.
	srv4, _, _ := toolServer(t, nil)
	resps = runServer(t, srv4, mustRequest(t, 79, "tools/call", map[string]any{
		"name":      "security.endpoint_discovery",
		"arguments": map[string]any{"tool": "nuclei", "target": "http://host.docker.internal:9090/"},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "capability") {
		t.Errorf("tool capability salah harus denied: %v", resps[0])
	}
	// (5) Case aborted → denied (kill switch §10).
	jobsRoot := t.TempDir()
	if _, err := jobs.MarkAborted(jobsRoot, "case-dead"); err != nil {
		t.Fatal(err)
	}
	srv5, _, _ := toolServer(t, func(c *Config) { c.JobsDir = jobsRoot })
	resps = runServer(t, srv5, mustRequest(t, 80, "tools/call", map[string]any{
		"name":      "security.endpoint_discovery",
		"arguments": map[string]any{"tool": "httpx", "target": "http://host.docker.internal:9090/", "case": "case-dead"},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "abort") {
		t.Errorf("case aborted harus denied: %v", resps[0])
	}
	// (6) Image tidak ada di daemon → denied (tanpa pull otomatis).
	resps = runServer(t, newServerWithMissingImage(t), mustRequest(t, 81, "tools/call", map[string]any{
		"name":      "security.endpoint_discovery",
		"arguments": map[string]any{"tool": "httpx", "target": "http://host.docker.internal:9090/"},
	}))
	res, ok = resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "tidak ada di daemon") {
		t.Errorf("image hilang harus denied: %v", resps[0])
	}
}

// missingImageDocker: fake docker yang melaporkan image TIDAK ada.
type missingImageDocker struct{ fakeDocker }

func (m *missingImageDocker) Exec(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) > 1 && args[0] == "image" && args[1] == "inspect" {
		return nil, fmt.Errorf("No such image")
	}
	return m.fakeDocker.Exec(ctx, args...)
}

func newServerWithMissingImage(t *testing.T) *Server {
	t.Helper()
	srv, _, _ := toolServer(t, func(c *Config) {
		c.Docker = &missingImageDocker{fakeDocker{runFn: writeFakeToolResult()}}
	})
	return srv
}

func TestToolsCallTemplateBasedValidationSingleTool(t *testing.T) {
	srv, _, fd := toolServer(t, nil)
	// template_based_validation hanya punya nuclei: tanpa arg 'tool' jalan.
	resps := runServer(t, srv, mustRequest(t, 82, "tools/call", map[string]any{
		"name":      "security.template_based_validation",
		"arguments": map[string]any{"target": "http://host.docker.internal:9090/", "case": "case-nuc"},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true {
		t.Fatalf("nuclei conditional TANPA approval harus denied: %v", resps[0])
	}
	if txt := callText(t, resps[0]); !strings.Contains(txt, "approval") {
		t.Errorf("nuclei harus butuh approval (conditional): %s", txt)
	}
	if len(fd.runs()) != 0 {
		t.Errorf("nuclei denied tidak boleh mengeksekusi container")
	}
}

// ------------------------------------------------------------ request_mutation

func TestToolsCallRequestMutationForwarded(t *testing.T) {
	var gotMethod, gotURL string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotMethod, _ = req["method"].(string)
		gotURL, _ = req["url"].(string)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "executed"})
	}))
	defer proxy.Close()

	srv, store := newTestServer(t, map[string]any{
		"request_mutation": map[string]any{
			"risk": "medium", "default_provider": "proxy",
			"requires_scope": true, "requires_network": true,
			"requires_approval": "conditional",
		},
	}, func(c *Config) { c.ProxyURL = proxy.URL })
	if err := store.Save(approval.Record{
		CaseID: "case-mut", Capability: "request_mutation", Host: "localhost",
		Method: "POST", Path: "/orders/1/status", MaxRequests: 2,
		ExpiresAt: time.Now().Add(time.Hour).UTC(), Risk: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	resps := runServer(t, srv, mustRequest(t, 90, "tools/call", map[string]any{
		"name": "security.request_mutation",
		"arguments": map[string]any{
			"url":    "http://localhost:8901/orders/1/status",
			"method": "POST",
			"body":   `{"state":"shipped"}`,
			"case":   "case-mut",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("request_mutation dengan approval harus forwarded: %v", resps[0])
	}
	if gotMethod != "POST" || gotURL != "http://localhost:8901/orders/1/status" {
		t.Errorf("payload proxy salah: %s %s", gotMethod, gotURL)
	}
	if !strings.Contains(callText(t, resps[0]), "executed") {
		t.Errorf("response proxy harus diteruskan: %s", callText(t, resps[0]))
	}
}

func TestToolsCallSelectPayloadIsBoundedAndNonExecuting(t *testing.T) {
	reg, err := payload.Load(filepath.Join("..", "payload", "testdata", "registry.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	fd := &fakeDocker{}
	srv, _ := newTestServer(t, nil, func(c *Config) {
		c.PayloadRegistry = reg
		c.Docker = fd
		c.Policy.Limits.MaxRequestsTotal = 2
	})
	resps := runServer(t, srv, mustRequest(t, 110, "tools/call", map[string]any{
		"name": "security.select_payload",
		"arguments": map[string]any{
			"context": "query", "risk": "low", "max_entries": 10, "budget": 2,
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("payload selection harus observed: %v", resps[0])
	}
	var body struct {
		Status   string `json:"status"`
		Provider string `json:"provider"`
		Payloads []struct {
			ID   string `json:"id"`
			Risk string `json:"risk"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal([]byte(callText(t, resps[0])), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "selected" || body.Provider != "payload" || len(body.Payloads) != 1 ||
		body.Payloads[0].ID != "sql-basic" || body.Payloads[0].Risk != string(risk.LevelLow) {
		t.Fatalf("selection salah: %+v", body)
	}
	if len(fd.runs()) != 0 {
		t.Fatalf("payload selection tidak boleh mengeksekusi Docker: %v", fd.runs())
	}
}

func TestToolsCallSelectPayloadFailsClosedAndIgnoresTargetContent(t *testing.T) {
	reg, err := payload.Load(filepath.Join("..", "payload", "testdata", "registry.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := newTestServer(t, nil, func(c *Config) {
		c.PayloadRegistry = reg
		c.Policy.Limits.MaxRequestsTotal = 2
	})
	resps := runServer(t, srv, mustRequest(t, 111, "tools/call", map[string]any{
		"name": "security.select_payload",
		"arguments": map[string]any{
			"context": "query", "risk": "low", "budget": 2,
			"target": "destructive credential exfiltration payload",
		},
	}))
	if resps[0]["result"].(map[string]any)["isError"] == true {
		t.Fatalf("target content must not alter safe selection: %v", resps[0])
	}
	srv2, _ := newTestServer(t, nil, nil)
	resps = runServer(t, srv2, mustRequest(t, 112, "tools/call", map[string]any{
		"name":      "security.select_payload",
		"arguments": map[string]any{"context": "query", "risk": "low", "budget": 1},
	}))
	if resps[0]["result"].(map[string]any)["isError"] != true || !strings.Contains(callText(t, resps[0]), "fail-closed") {
		t.Fatalf("missing payload registry must deny fail-closed: %v", resps[0])
	}
	bad := testPolicy()
	bad.Limits.DestructivePayloads = "allow"
	srv3, _ := newTestServer(t, nil, func(c *Config) { c.PayloadRegistry = reg; c.Policy = bad })
	resps = runServer(t, srv3, mustRequest(t, 113, "tools/call", map[string]any{
		"name":      "security.select_payload",
		"arguments": map[string]any{"context": "query", "risk": "low", "budget": 1},
	}))
	if resps[0]["result"].(map[string]any)["isError"] != true || !strings.Contains(callText(t, resps[0]), "policy") {
		t.Fatalf("unsafe payload policy must deny: %v", resps[0])
	}
}

func TestToolsCallCriticalToolRiskIsDisabled(t *testing.T) {
	// A tool may be more dangerous than its capability. The effective risk
	// must enforce the critical kill-switch before Docker is reached.
	srv, _, fd := toolServer(t, func(c *Config) {
		reg, err := toolregistry.FromMap(map[string]any{"tools": map[string]any{
			"httpx": map[string]any{
				"name": "httpx", "category": "url-probing",
				"image": "hermes-tool-httpx", "version": "1.12.0",
				"digest": "-", "signature_required": true, "risk": "critical", "provider": "docker",
				"capability": "endpoint_discovery", "network_requirement": "target-http",
				"approval_requirement": "automatic", "evidence_parser": "validation-result-json",
			},
		}})
		if err != nil {
			t.Fatalf("critical tool registry: %v", err)
		}
		c.ToolRegistry = reg
	})
	resps := runServer(t, srv, mustRequest(t, 100, "tools/call", map[string]any{
		"name": "security.endpoint_discovery",
		"arguments": map[string]any{
			"tool": "httpx", "target": "http://host.docker.internal:9090/", "case": "case-critical",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true || !strings.Contains(callText(t, resps[0]), "critical") {
		t.Fatalf("critical tool risk harus disabled: %v", resps[0])
	}
	if len(fd.runs()) != 0 {
		t.Fatalf("critical tool tidak boleh mencapai Docker: %v", fd.runs())
	}
}
