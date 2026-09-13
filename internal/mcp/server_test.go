package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/capability"
	"hermes-security-skills/internal/jobs"
	"hermes-security-skills/internal/policy"
	"hermes-security-skills/internal/proxycore"
	"hermes-security-skills/internal/scope"
)

// testPolicy: policy in-memory (automatic/conditional/approval_required/
// disabled sesuai ROADMAP 8) tanpa perlu file di disk.
func testPolicy() *policy.Policy {
	return &policy.Policy{
		Risk: &policy.RiskPolicy{DefaultAction: map[string]string{
			"low": "automatic", "medium": "conditional",
			"high": "approval_required", "critical": "disabled",
		}},
		Limits: &policy.PolicyLimits{
			MaxEntriesPerTask: 1, MaxRequestsTotal: 1, RateLimitRPS: 1, MaxConcurrency: 1,
			StopOn429: true, StopOnRepeated5xx: true,
			DestructivePayloads: "deny", ExfiltrationPayloads: "deny", CredentialAttackLists: "deny",
		},
	}
}

// registry dari map capability (tanpa file).
func testRegistry(t *testing.T, extra map[string]any) *capability.Registry {
	t.Helper()
	caps := map[string]any{
		"request_replay": map[string]any{
			"risk": "medium", "default_provider": "proxy",
			"requires_scope": true, "requires_network": true,
			"requires_approval": "conditional",
		},
		"inspect_request": map[string]any{
			"risk": "low", "default_provider": "proxy",
			"requires_scope": true, "requires_network": false,
		},
		"list_history": map[string]any{
			"risk": "low", "default_provider": "proxy",
			"requires_scope": false, "requires_network": false,
		},
		"response_comparison": map[string]any{
			"risk": "low", "default_provider": "proxy",
			"requires_scope": true, "requires_network": false,
		},
		"json_diff": map[string]any{
			"risk": "low", "default_provider": "local",
			"requires_scope": false, "requires_network": false,
		},
	}
	for k, v := range extra {
		caps[k] = v
	}
	reg, err := capability.FromMap(map[string]any{"capabilities": caps})
	if err != nil {
		t.Fatalf("registry test: %v", err)
	}
	return reg
}

// newTestServer: server lengkap dengan scope allowlist localhost:8901 dan
// approval store sementara. Bila mutate tidak mengganti EvidenceDir, server
// memakai evidence dir fixture (2 entri: orders/1 GET 200, orders/2 POST 404).
func newTestServer(t *testing.T, extraCaps map[string]any, mutate func(*Config)) (*Server, *approval.Store) {
	t.Helper()
	store := approval.OpenStore(filepath.Join(t.TempDir(), "approvals.json"))
	cfg := Config{
		Registry:    testRegistry(t, extraCaps),
		Policy:      testPolicy(),
		Scope:       mustChecker(t, []string{"localhost:8901"}),
		ProxyURL:    "http://proxy-unused", // diganti per-test bila perlu
		Store:       store,
		JobsDir:     t.TempDir(),
		EvidenceDir: writeTestEvidence(t),
		Audit:       func(string, map[string]any) error { return nil },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, store
}

// writeTestEvidence membuat evidence fixture via proxycore (format identik
// dengan hermes-proxy) dan mengembalikan path dir-nya.
func writeTestEvidence(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	es, err := proxycore.NewEvidenceStore(dir)
	if err != nil {
		t.Fatalf("NewEvidenceStore: %v", err)
	}
	base := proxycore.EvidenceRequest{
		Method:       "GET",
		URL:          "http://localhost:8901/orders/1",
		Headers:      proxycore.RedactHeaders(http.Header{"Authorization": {"Bearer sekret"}}),
		BodyEncoding: "base64",
	}
	resp1 := proxycore.EvidenceResponse{
		Status:       200,
		Headers:      proxycore.RedactHeaders(http.Header{"Content-Type": {"application/json"}}),
		BodyBase64:   base64.StdEncoding.EncodeToString([]byte(`{"id":1}`)),
		BodyEncoding: "base64",
	}
	rec2 := proxycore.EvidenceRecord{
		Request: proxycore.EvidenceRequest{
			Method:       "POST",
			URL:          "http://localhost:8901/orders/1/status",
			Headers:      proxycore.RedactHeaders(http.Header{}),
			BodyBase64:   base64.StdEncoding.EncodeToString([]byte(`{"state":"shipped"}`)),
			BodyEncoding: "base64",
		},
		Response: proxycore.EvidenceResponse{
			Status:       404,
			Headers:      proxycore.RedactHeaders(http.Header{"Content-Type": {"application/json"}}),
			BodyBase64:   base64.StdEncoding.EncodeToString([]byte(`{"error":"not found"}`)),
			BodyEncoding: "base64",
		},
	}
	for _, rec := range []proxycore.EvidenceRecord{
		{Request: base, Response: resp1},
		rec2,
	} {
		if _, _, err := es.Write(rec); err != nil {
			t.Fatalf("Write evidence: %v", err)
		}
	}
	return dir
}

func mustChecker(t *testing.T, hosts []string) *scope.Checker {
	t.Helper()
	c, err := scope.NewChecker(hosts)
	if err != nil {
		t.Fatalf("checker: %v", err)
	}
	return c
}

// runServer menjalankan Serve dengan input baris JSON-RPC dan mengembalikan
// semua response (satu per baris) ter-parse.
func runServer(t *testing.T, srv *Server, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := srv.Serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	got := strings.Split(strings.TrimSpace(out.String()), "\n")
	if out.Len() == 0 {
		return nil
	}
	resps := make([]map[string]any, 0, len(got))
	for i, ln := range got {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("response %d bukan JSON valid: %v (%q)", i+1, err, ln)
		}
		resps = append(resps, m)
	}
	return resps
}

func mustRequest(t *testing.T, id int, method string, params any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInitialize(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 1, "initialize", map[string]any{}))
	if len(resps) != 1 {
		t.Fatalf("mau 1 response, dapat %d", len(resps))
	}
	r := resps[0]
	if _, ok := r["error"]; ok {
		t.Fatalf("initialize tidak boleh error: %v", r)
	}
	res, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("result hilang: %v", r)
	}
	if res["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v, mau %s", res["protocolVersion"], ProtocolVersion)
	}
	caps, _ := res["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Errorf("capabilities.tools harus ada: %v", caps)
	}
	info, _ := res["serverInfo"].(map[string]any)
	if info["name"] != ServerName || info["version"] != ServerVersion {
		t.Errorf("serverInfo salah: %v", info)
	}
}

func TestNotificationInitializedNoResponse(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	var out bytes.Buffer
	err := srv.Serve(strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"), &out)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("notification tidak boleh dijawab, dapat: %s", out.String())
	}
}

func TestPing(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 7, "ping", nil))
	if len(resps) != 1 {
		t.Fatalf("mau 1 response, dapat %d", len(resps))
	}
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || len(res) != 0 {
		t.Errorf("ping harus balas result {} — dapat %v", resps[0])
	}
}

func TestToolsListOneToolPerCapability(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 2, "tools/list", nil))
	res := resps[0]["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	if len(tools) != 5 { // request_replay, inspect_request, list_history, response_comparison, json_diff
		t.Fatalf("mau 5 tool, dapat %d", len(tools))
	}
	// Schema: request_replay (network) wajib url+method; list_history punya
	// schema filter read-only.
	var replaySchema, histSchema map[string]any
	for _, raw := range tools {
		tl := raw.(map[string]any)
		switch tl["name"] {
		case "request_replay":
			replaySchema = tl["inputSchema"].(map[string]any)
			if strings.TrimSpace(tl["description"].(string)) == "" {
				t.Error("request_replay harus punya description")
			}
		case "list_history":
			histSchema = tl["inputSchema"].(map[string]any)
		case "response_comparison":
			schema := tl["inputSchema"].(map[string]any)
			req, _ := schema["required"].([]any)
			if len(req) != 2 {
				t.Errorf("response_comparison required = %v, mau [evidence_ref_a evidence_ref_b]", req)
			}
		case "json_diff":
			schema := tl["inputSchema"].(map[string]any)
			req, _ := schema["required"].([]any)
			if len(req) != 2 {
				t.Errorf("json_diff required = %v, mau [json_a json_b]", req)
			}
		}
	}
	req, _ := replaySchema["required"].([]any)
	if len(req) != 2 || req[0] != "url" || req[1] != "method" {
		t.Errorf("request_replay required = %v, mau [url method]", req)
	}
	props, _ := replaySchema["properties"].(map[string]any)
	for _, f := range []string{"url", "method", "headers", "body", "case"} {
		if _, ok := props[f]; !ok {
			t.Errorf("request_replay schema kurang field %q: %v", f, props)
		}
	}
	hprops, _ := histSchema["properties"].(map[string]any)
	for _, f := range []string{"limit", "url_substring", "method", "status_min"} {
		if _, ok := hprops[f]; !ok {
			t.Errorf("list_history schema kurang field %q: %v", f, hprops)
		}
	}
	if _, ok := histSchema["required"]; ok {
		t.Errorf("list_history tidak punya required: %v", histSchema)
	}
}

func TestToolsCallUnknownToolAndUnknownMethod(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	// Unknown tool → -32602.
	resps := runServer(t, srv, mustRequest(t, 3, "tools/call", map[string]any{
		"name": "tidak_ada", "arguments": map[string]any{},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("unknown tool harus -32602, dapat %v", resps[0])
	}
	// Unknown method → -32601.
	resps = runServer(t, srv, mustRequest(t, 4, "bogus/method", nil))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeMethodNotFound) {
		t.Errorf("unknown method harus -32601, dapat %v", resps[0])
	}
	// ID harus di-echo.
	if resps[0]["id"] != float64(4) {
		t.Errorf("id harus di-echo, dapat %v", resps[0]["id"])
	}
}

func TestParseError32700(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, "ini bukan json{{{")
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeParseError) {
		t.Errorf("parse error harus -32700, dapat %v", resps[0])
	}
	if resps[0]["id"] != nil {
		// id harus null (JSON null → Go nil setelah unmarshal ke any)
		t.Errorf("parse error id harus null, dapat %v", resps[0]["id"])
	}
}

func TestToolsCallDenyCritical(t *testing.T) {
	srv, _ := newTestServer(t, map[string]any{
		"credential_attack": map[string]any{
			"risk": "critical", "default_provider": "proxy",
			"requires_scope": true, "requires_network": true,
		},
	}, nil)
	resps := runServer(t, srv, mustRequest(t, 5, "tools/call", map[string]any{
		"name": "credential_attack",
		"arguments": map[string]any{
			"url": "http://localhost:8901/", "method": "GET",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok {
		t.Fatalf("result hilang: %v", resps[0])
	}
	if res["isError"] != true {
		t.Fatalf("critical harus isError=true: %v", res)
	}
	content := res["content"].([]any)[0].(map[string]any)
	if !strings.Contains(content["text"].(string), "disabled") {
		t.Errorf("reason harus menyebut disabled: %v", content["text"])
	}
}

func TestToolsCallDenyPostWithoutApproval(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	// POST → risk HIGH → approval_required → ditolak (approval store kosong).
	resps := runServer(t, srv, mustRequest(t, 6, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": "http://localhost:8901/login", "method": "POST",
			"body": "user=a&pass=b",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] != true {
		t.Fatalf("POST tanpa approval harus isError=true: %v", resps[0])
	}
	content := res["content"].([]any)[0].(map[string]any)
	txt := content["text"].(string)
	if !strings.Contains(txt, "denied") || !strings.Contains(txt, "approval") {
		t.Errorf("denial harus menyebut denied+approval: %s", txt)
	}
	// Body (mengandung kredensial) TIDAK boleh bocor ke response audit
	// maupun ke luar — konten denial hanya alasan policy.
	if strings.Contains(txt, "user=a&pass=b") {
		t.Error("KEBOCORAN: body request ikut dikembalikan dalam denial")
	}
}

func TestToolsCallDenyScopeLoopback(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	// IP literal loopback ditolak keras oleh scope (§8) walau GET.
	resps := runServer(t, srv, mustRequest(t, 8, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": "http://127.0.0.1:8901/", "method": "GET",
		},
	}))
	res := resps[0]["result"].(map[string]any)
	content := res["content"].([]any)[0].(map[string]any)
	if !strings.Contains(content["text"].(string), "scope") {
		t.Errorf("denial harus dari scope check: %v", content["text"])
	}
}

func TestToolsCallForwardedViaProxyWithApproval(t *testing.T) {
	// Stub hermes-proxy control channel.
	var gotBody map[string]any
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/execute" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "would_execute", "url": gotBody["url"], "method": gotBody["method"],
		})
	}))
	defer proxy.Close()

	approvalUsed := 0
	srv, store := newTestServer(t, nil, func(c *Config) {
		c.ProxyURL = proxy.URL
		base := c.Audit
		c.Audit = func(action string, detail map[string]any) error {
			if action == "mcp_tools_call" && detail["decision"] == "forwarded" {
				approvalUsed++
			}
			return base(action, detail)
		}
	})
	// Seed scoped approval: request_replay GET localhost (path wildcard).
	exp := time.Now().Add(time.Hour).UTC()
	if err := store.Save(approval.Record{
		CaseID: "case-demo", Capability: "request_replay", Host: "localhost",
		Method: "GET", Path: approval.PathAny, MaxRequests: 2,
		ExpiresAt: exp, Risk: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	resps := runServer(t, srv, mustRequest(t, 9, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": "http://localhost:8901/orders/1", "method": "GET",
			"case": "case-demo",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("GET dengan approval harus forwarded: %v", resps[0])
	}
	content := res["content"].([]any)[0].(map[string]any)
	if !strings.Contains(content["text"].(string), "would_execute") {
		t.Errorf("response proxy harus diteruskan: %v", content["text"])
	}
	// Control channel menerima {url, method} yang benar.
	if gotBody["method"] != "GET" || gotBody["url"] != "http://localhost:8901/orders/1" {
		t.Errorf("payload proxy salah: %v", gotBody)
	}
	// Budget approval terkonsumsi 1.
	recs, _ := store.Load()
	if len(recs) != 1 || recs[0].Used != 1 {
		t.Errorf("budget approval harus terkonsumsi: %+v", recs)
	}
	if approvalUsed != 1 {
		t.Errorf("audit 'forwarded' harus tercatat 1x, dapat %d", approvalUsed)
	}
}

func TestToolsCallConditionalDeniedWithoutApproval(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 10, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": "http://localhost:8901/", "method": "GET",
		},
	}))
	res := resps[0]["result"].(map[string]any)
	content := res["content"].([]any)[0].(map[string]any)
	txt := content["text"].(string)
	if !strings.Contains(txt, "conditional") {
		t.Errorf("GET tanpa approval harus ditolak action=conditional: %s", txt)
	}
}

func TestToolsCallAbortedCaseDenied(t *testing.T) {
	jobsRoot := t.TempDir()
	if _, err := jobs.MarkAborted(jobsRoot, "case-abort"); err != nil {
		t.Fatal(err)
	}
	srv, store := newTestServer(t, nil, func(c *Config) { c.JobsDir = jobsRoot })
	// Approval tetap aktif — tapi case di-abort: harus ditolak duluan.
	exp := time.Now().Add(time.Hour).UTC()
	if err := store.Save(approval.Record{
		CaseID: "case-abort", Capability: "request_replay", Host: "localhost",
		Method: "GET", Path: approval.PathAny, MaxRequests: 5,
		ExpiresAt: exp, Risk: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	resps := runServer(t, srv, mustRequest(t, 11, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": "http://localhost:8901/", "method": "GET", "case": "case-abort",
		},
	}))
	res := resps[0]["result"].(map[string]any)
	content := res["content"].([]any)[0].(map[string]any)
	if !strings.Contains(content["text"].(string), "abort") {
		t.Errorf("case aborted harus ditolak: %v", content["text"])
	}
}

// list_history kini NYATA: index event store dari --evidence-dir.
func TestToolsCallListHistoryFromEventStore(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 12, "tools/call", map[string]any{
		"name": "list_history", "arguments": map[string]any{},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("list_history harus sukses: %v", resps[0])
	}
	content := res["content"].([]any)[0].(map[string]any)
	var body struct {
		Status   string `json:"status"`
		Provider string `json:"provider"`
		Count    int    `json:"count"`
		Entries  []struct {
			Seq         int64  `json:"seq"`
			URL         string `json:"url"`
			Method      string `json:"method"`
			Status      int    `json:"status"`
			EvidenceRef string `json:"evidence_ref"`
			SHA256      string `json:"sha256"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(content["text"].(string)), &body); err != nil {
		t.Fatalf("payload bukan JSON: %v (%s)", err, content["text"])
	}
	if body.Status != "observed" || body.Provider != "event-store" {
		t.Fatalf("status/provider salah: %+v", body)
	}
	if body.Count != 2 || len(body.Entries) != 2 {
		t.Fatalf("mau 2 entry nyata, dapat %d (%d)", body.Count, len(body.Entries))
	}
	e1 := body.Entries[0]
	if e1.Seq != 1 || e1.Method != "GET" || e1.Status != 200 ||
		e1.URL != "http://localhost:8901/orders/1" || e1.EvidenceRef != "evidence-000001.json" || len(e1.SHA256) != 64 {
		t.Errorf("entry[0] salah: %+v", e1)
	}
	if body.Entries[1].Method != "POST" || body.Entries[1].Status != 404 {
		t.Errorf("entry[1] salah: %+v", body.Entries[1])
	}
}

func TestToolsCallListHistoryFilterAndLimit(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 20, "tools/call", map[string]any{
		"name": "list_history",
		"arguments": map[string]any{
			"url_substring": "orders/1/status", "method": "post", "status_min": 300,
		},
	}))
	content := resps[0]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	var body struct {
		Count   int `json:"count"`
		Entries []struct {
			Seq int64 `json:"seq"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(content["text"].(string)), &body); err != nil {
		t.Fatal(err)
	}
	if body.Count != 1 || len(body.Entries) != 1 || body.Entries[0].Seq != 2 {
		t.Errorf("filter salah: %+v", body)
	}
	// Limit mempertahankan entri terbaru.
	resps = runServer(t, srv, mustRequest(t, 21, "tools/call", map[string]any{
		"name": "list_history", "arguments": map[string]any{"limit": 1},
	}))
	content = resps[0]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	if err := json.Unmarshal([]byte(content["text"].(string)), &body); err != nil {
		t.Fatal(err)
	}
	if body.Count != 1 || body.Entries[0].Seq != 2 {
		t.Errorf("limit harus ambil terbaru: %+v", body)
	}
}

func TestToolsCallInspectRequestFromEventStore(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 22, "tools/call", map[string]any{
		"name": "inspect_request",
		"arguments": map[string]any{
			"evidence_ref": "evidence-000001.json",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("inspect_request harus sukses: %v", resps[0])
	}
	content := res["content"].([]any)[0].(map[string]any)
	var body struct {
		Status string `json:"status"`
		Detail struct {
			EvidenceRef string `json:"evidence_ref"`
			Seq         int64  `json:"seq"`
			Request     struct {
				Method  string              `json:"method"`
				URL     string              `json:"url"`
				Headers map[string][]string `json:"headers"`
			} `json:"request"`
			Response struct {
				Status  int                 `json:"status"`
				Body    string              `json:"body"`
				Headers map[string][]string `json:"headers"`
			} `json:"response"`
		} `json:"detail"`
	}
	if err := json.Unmarshal([]byte(content["text"].(string)), &body); err != nil {
		t.Fatalf("payload bukan JSON: %v", err)
	}
	if body.Status != "observed" || body.Detail.Seq != 1 ||
		body.Detail.Request.Method != "GET" || body.Detail.Request.URL != "http://localhost:8901/orders/1" {
		t.Fatalf("detail salah: %+v", body)
	}
	if body.Detail.Response.Status != 200 || body.Detail.Response.Body != `{"id":1}` {
		t.Errorf("response detail salah: %+v", body.Detail.Response)
	}
	// Header tetap ter-redaksi seperti di evidence file (§24/§25).
	auth := body.Detail.Request.Headers["Authorization"]
	if len(auth) != 1 || auth[0] != "[REDACTED]" {
		t.Errorf("Authorization harus [REDACTED], dapat %v", auth)
	}
}

func TestToolsCallInspectRequestFailClosed(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	// Ref tidak ada → -32602.
	resps := runServer(t, srv, mustRequest(t, 23, "tools/call", map[string]any{
		"name": "inspect_request", "arguments": map[string]any{"evidence_ref": "evidence-999999.json"},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("ref tidak ada harus -32602, dapat %v", resps[0])
	}
	// Path traversal ditolak.
	resps = runServer(t, srv, mustRequest(t, 24, "tools/call", map[string]any{
		"name": "inspect_request", "arguments": map[string]any{"evidence_ref": "../evidence-000001.json"},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("path traversal harus -32602, dapat %v", resps[0])
	}
	// Argumen hilang.
	resps = runServer(t, srv, mustRequest(t, 25, "tools/call", map[string]any{
		"name": "inspect_request", "arguments": map[string]any{},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("evidence_ref hilang harus -32602, dapat %v", resps[0])
	}
}

func TestToolsCallResponseComparisonRealDiff(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 26, "tools/call", map[string]any{
		"name": "response_comparison",
		"arguments": map[string]any{
			"evidence_ref_a": "evidence-000001.json",
			"evidence_ref_b": "evidence-000002.json",
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("response_comparison harus sukses: %v", resps[0])
	}
	content := res["content"].([]any)[0].(map[string]any)
	var body struct {
		Status       string `json:"status"`
		StatusA      int    `json:"status_a"`
		StatusB      int    `json:"status_b"`
		Observations []struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
		} `json:"observations"`
	}
	if err := json.Unmarshal([]byte(content["text"].(string)), &body); err != nil {
		t.Fatalf("payload bukan JSON: %v", err)
	}
	if body.Status != "observed" || body.StatusA != 200 || body.StatusB != 404 {
		t.Fatalf("header comparison salah: %+v", body)
	}
	types := map[string]bool{}
	for _, o := range body.Observations {
		types[o.Type] = true
		if o.Detail == "" {
			t.Errorf("observation tanpa detail: %+v", o)
		}
	}
	if !types["status_diff"] || !types["body_diff"] {
		t.Errorf("harus ada status_diff dan body_diff (beda status + beda body): %+v", body.Observations)
	}
}

func TestToolsCallJSONDiffReal(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 27, "tools/call", map[string]any{
		"name": "json_diff",
		"arguments": map[string]any{
			"json_a": map[string]any{"a": 1, "b": "sama"},
			"json_b": map[string]any{"a": 2, "b": "sama"},
		},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("json_diff harus sukses: %v", resps[0])
	}
	content := res["content"].([]any)[0].(map[string]any)
	var body struct {
		Status       string `json:"status"`
		Provider     string `json:"provider"`
		Observations []struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
		} `json:"observations"`
	}
	if err := json.Unmarshal([]byte(content["text"].(string)), &body); err != nil {
		t.Fatalf("payload bukan JSON: %v", err)
	}
	if body.Status != "observed" || body.Provider != "local" {
		t.Fatalf("status/provider salah: %+v", body)
	}
	if len(body.Observations) != 1 || body.Observations[0].Type != "json_diff" ||
		!strings.Contains(body.Observations[0].Detail, "$.a: 1 -> 2") {
		t.Errorf("diff salah: %#v", body.Observations)
	}
	// Identik = kosong; argumen hilang = -32602.
	resps = runServer(t, srv, mustRequest(t, 28, "tools/call", map[string]any{
		"name": "json_diff",
		"arguments": map[string]any{
			"json_a": map[string]any{"a": 1}, "json_b": map[string]any{"a": 1},
		},
	}))
	content = resps[0]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	if err := json.Unmarshal([]byte(content["text"].(string)), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Observations) != 0 {
		t.Errorf("json identik harus tanpa observation: %#v", body.Observations)
	}
	resps = runServer(t, srv, mustRequest(t, 29, "tools/call", map[string]any{
		"name": "json_diff", "arguments": map[string]any{"json_a": map[string]any{}},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("json_b hilang harus -32602, dapat %v", resps[0])
	}
}

// Read-only capability TANPA provider lokal (openapi_analysis/docker) tetap
// stub informatif — jujur, tidak mengeksekusi apa pun.
func TestToolsCallReadOnlyFallbackStub(t *testing.T) {
	srv, _ := newTestServer(t, map[string]any{
		"openapi_analysis": map[string]any{
			"risk": "low", "default_provider": "docker",
			"requires_scope": false, "requires_network": false,
		},
	}, nil)
	resps := runServer(t, srv, mustRequest(t, 30, "tools/call", map[string]any{
		"name": "openapi_analysis", "arguments": map[string]any{},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok || res["isError"] == true {
		t.Fatalf("fallback stub tidak boleh error: %v", resps[0])
	}
	content := res["content"].([]any)[0].(map[string]any)
	if !strings.Contains(content["text"].(string), "stub") {
		t.Errorf("fallback harus stub informatif: %v", content["text"])
	}
}

// Kill switch §10 tetap berlaku untuk operasi read-only bila 'case' disertakan.
func TestToolsCallReadOnlyAbortedCaseDenied(t *testing.T) {
	jobsRoot := t.TempDir()
	if _, err := jobs.MarkAborted(jobsRoot, "case-abort"); err != nil {
		t.Fatal(err)
	}
	srv, _ := newTestServer(t, nil, func(c *Config) { c.JobsDir = jobsRoot })
	resps := runServer(t, srv, mustRequest(t, 31, "tools/call", map[string]any{
		"name":      "list_history",
		"arguments": map[string]any{"case": "case-abort"},
	}))
	res, ok := resps[0]["result"].(map[string]any)
	if !ok {
		t.Fatalf("result hilang: %v", resps[0])
	}
	content := res["content"].([]any)[0].(map[string]any)
	if res["isError"] != true || !strings.Contains(content["text"].(string), "abort") {
		t.Errorf("case aborted harus ditolak walau read-only: %v", content["text"])
	}
}

// Tanpa --evidence-dir, tool event store menolak dengan pesan jelas
// (fail-closed, tanpa silent degrade).
func TestToolsCallEventStoreWithoutEvidenceDir(t *testing.T) {
	srv, _ := newTestServer(t, nil, func(c *Config) { c.EvidenceDir = "" })
	resps := runServer(t, srv, mustRequest(t, 32, "tools/call", map[string]any{
		"name": "list_history", "arguments": map[string]any{},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("evidence-dir kosong harus -32602, dapat %v", resps[0])
	}
}

func TestToolsCallProxyDownFailClosed(t *testing.T) {
	srv, store := newTestServer(t, nil, func(c *Config) {
		c.ProxyURL = "http://127.0.0.1:1" // port mati — koneksi pasti gagal
	})
	exp := time.Now().Add(time.Hour).UTC()
	if err := store.Save(approval.Record{
		CaseID: "c", Capability: "request_replay", Host: "localhost",
		Method: "GET", Path: approval.PathAny, MaxRequests: 5,
		ExpiresAt: exp, Risk: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	resps := runServer(t, srv, mustRequest(t, 13, "tools/call", map[string]any{
		"name":      "request_replay",
		"arguments": map[string]any{"url": "http://localhost:8901/", "method": "GET", "case": "c"},
	}))
	res := resps[0]["result"].(map[string]any)
	content := res["content"].([]any)[0].(map[string]any)
	if !strings.Contains(content["text"].(string), "error") {
		t.Errorf("proxy down harus error fail-closed: %v", content["text"])
	}
}

func TestServerRejectsBadConfig(t *testing.T) {
	if _, err := NewServer(Config{Policy: testPolicy(), ProxyURL: "http://x"}); err == nil {
		t.Error("registry nil harus error")
	}
	reg := testRegistry(t, nil)
	if _, err := NewServer(Config{Registry: reg, Policy: testPolicy()}); err == nil {
		t.Error("proxy-url kosong harus error")
	}
	if _, err := NewServer(Config{Registry: reg, ProxyURL: "http://x", PolicyDir: "tidak-ada"}); err == nil {
		t.Error("policy dir tidak ada harus error (fail-closed)")
	}
}
