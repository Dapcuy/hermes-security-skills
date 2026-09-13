package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/capability"
	"hermes-security-skills/internal/jobs"
	"hermes-security-skills/internal/policy"
	"hermes-security-skills/internal/risk"
	"hermes-security-skills/internal/scope"
	"hermes-security-skills/internal/yamlmini"
)

// ServerName/ServerVersion diumumkan pada initialize.
const (
	ServerName    = "hermes-security"
	ServerVersion = "0.1.0"
)

// Config server MCP. Semua komponen policy injectable agar testable;
// pada produksi cmd/hermes-security mengisi dari flag CLI.
type Config struct {
	Registry  *capability.Registry // allowlist tool (§4.3: Hermes hanya melihat tool dari registry)
	Policy    *policy.Policy       // risk.yaml + limits.yaml (nil = load dari PolicyDir)
	PolicyDir string               // direktori policy (dipakai bila Policy nil)
	Scope     *scope.Checker       // scope rules in-line (nil = load dari ScopeFile)
	ScopeFile string               // file scope rules YAML {allowed_hosts}
	ProxyURL  string               // base URL control channel hermes-proxy
	Store     *approval.Store      // approval store (nil = conditional/approval_required selalu ditolak — fail-closed)
	JobsDir   string               // root jobs untuk cek abort marker (§10)
	Version   string               // override versi server (default ServerVersion)
	Now       func() time.Time     // injectable clock (reserved untuk test)
	HTTP      *http.Client         // injectable client untuk test (default timeout 10s)
	Audit     func(action string, detail map[string]any) error
}

// Server MCP minimal: initialize, notifications/initialized, tools/list,
// tools/call, ping. Satu MCP tool per capability registry.
type Server struct {
	cfg     Config
	pol     *policy.Policy
	version string
}

// NewServer memvalidasi konfigurasi dan membangun Server. Fail-closed:
// registry nil / policy tidak bisa dimuat = error — server tidak jalan.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Registry == nil {
		return nil, errors.New("mcp: registry capability wajib (allowlist tool, §4.3)")
	}
	if strings.TrimSpace(cfg.ProxyURL) == "" {
		return nil, errors.New("mcp: proxy-url wajib (satu-satunya jalur egress, §11)")
	}
	pol := cfg.Policy
	if pol == nil {
		var err error
		pol, err = policy.Load(cfg.PolicyDir)
		if err != nil {
			return nil, fmt.Errorf("mcp: load policy: %w", err)
		}
	}
	version := cfg.Version
	if version == "" {
		version = ServerVersion
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	return &Server{cfg: cfg, pol: pol, version: version}, nil
}

// Serve menjalankan loop utama: baca baris JSON-RPC dari r, tulis satu
// baris response per request ke w. Notification (tanpa id) tidak dijawab.
// Berhenti (nil) saat EOF; error I/O lain diteruskan.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	bw := bufio.NewWriter(w)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		resp := s.handleLine([]byte(line))
		if resp == nil {
			continue // notification: tanpa response
		}
		out, err := json.Marshal(resp)
		if err != nil {
			out, _ = json.Marshal(rpcResponse{
				JSONRPC: "2.0", ID: resp.ID,
				Error: errInternal("response tidak dapat diserialisasi"),
			})
		}
		if _, err := bw.Write(append(out, '\n')); err != nil {
			return fmt.Errorf("mcp: tulis response: %w", err)
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("mcp: flush response: %w", err)
		}
	}
	return sc.Err()
}

// handleLine memproses satu baris JSON-RPC. Nil = notification (tanpa
// response). Parse error = -32700 dengan id null (fail-closed).
func (s *Server) handleLine(line []byte) *rpcResponse {
	var req rpcRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	if err := dec.Decode(&req); err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: errParse(err.Error())}
	}
	// Versi jsonrpc salah (jika diisi) ditolak; kosong ditoleransi
	// (sebagian client mengirim tanpa field versi).
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		if isNotification(req) {
			return nil
		}
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: errInvalidRequest(fmt.Sprintf("jsonrpc %q bukan \"2.0\"", req.JSONRPC))}
	}
	// Notification: tidak pernah dijawab (termasuk notifications/initialized
	// dan method notification tak dikenal — JSON-RPC 2.0).
	if isNotification(req) {
		return nil
	}
	switch req.Method {
	case "initialize":
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: s.initializeResult()}
	case "ping":
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: struct{}{}}
	case "tools/list":
		res, rerr := s.toolsList()
		if rerr != nil {
			return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rerr}
		}
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res}
	case "tools/call":
		res, rerr := s.toolsCall(req.Params)
		if rerr != nil {
			return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rerr}
		}
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res}
	default:
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: errMethodNotFound(req.Method)}
	}
}

func isNotification(req rpcRequest) bool {
	return len(req.ID) == 0 || string(bytes.TrimSpace(req.ID)) == "null"
}

// ---------------------------------------------------------------- initialize

type initializeResult struct {
	ProtocolVersion string            `json:"protocolVersion"`
	Capabilities    map[string]any    `json:"capabilities"`
	ServerInfo      map[string]string `json:"serverInfo"`
}

func (s *Server) initializeResult() initializeResult {
	return initializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    map[string]any{"tools": struct{}{}},
		ServerInfo:      map[string]string{"name": ServerName, "version": s.version},
	}
}

// ---------------------------------------------------------------- tools/list

type toolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

// capabilityDescriptions: deskripsi tool per capability. Registry v1 tidak
// menyimpan field description, jadi deskripsi dikelola di sini (satu baris
// per capability terdaftar); capability lain memakai deskripsi generik
// dari metadata registry.
var capabilityDescriptions = map[string]string{
	"inspect_request":     "Inspect a captured HTTP request (read-only, served from event store; no traffic to target).",
	"request_replay":      "Replay an HTTP request to an in-scope target through hermes-proxy. Policy (scope + risk + approval) dieksekusi in-line sebelum provider dipanggil (ROADMAP 4.3).",
	"response_comparison": "Compare two HTTP responses (read-only analysis).",
	"list_history":        "List captured proxy traffic history (read-only, no network).",
	"json_diff":           "Structural JSON diff (local provider, no network, no side effects).",
	"openapi_analysis":    "Analyze an OpenAPI specification via docker validator (network=none).",
}

func describeCapability(c capability.Capability) string {
	if d, ok := capabilityDescriptions[c.Name]; ok {
		return d
	}
	return fmt.Sprintf("Capability %q (risk=%s, provider=%s) dari capability registry.", c.Name, c.Risk, c.DefaultProvider)
}

// inputSchemaFor membangun JSON Schema sederhana per capability:
//   - requires_network: {url, method, headers?, body?, case?} — operasi
//     aktif ke target via proxy;
//   - requires_scope saja: {url, case?} — butuh target, tanpa eksekusi;
//   - read-only murni: {}.
func inputSchemaFor(c capability.Capability) any {
	props := map[string]any{}
	var required []string
	if c.RequiresNetwork {
		props["url"] = map[string]any{"type": "string", "description": "URL target absolut (http/https)"}
		props["method"] = map[string]any{"type": "string", "description": "HTTP method"}
		props["headers"] = map[string]any{"type": "object", "description": "header tambahan (string->string)"}
		props["body"] = map[string]any{"type": "string", "description": "body request (opsional)"}
		required = []string{"url", "method"}
	} else if c.RequiresScope {
		props["url"] = map[string]any{"type": "string", "description": "URL target absolut (http/https)"}
		required = []string{"url"}
	}
	if c.RequiresNetwork || c.RequiresScope {
		props["case"] = map[string]any{"type": "string", "description": "case id engagement (untuk approval + abort check)"}
	}
	schema := map[string]any{"type": "object"}
	if len(props) > 0 {
		schema["properties"] = props
		if len(required) > 0 {
			schema["required"] = required
		}
	}
	return schema
}

func (s *Server) toolsList() (map[string]any, *rpcError) {
	tools := make([]toolDef, 0, s.cfg.Registry.Count())
	for _, c := range s.cfg.Registry.List() {
		tools = append(tools, toolDef{
			Name:        c.Name,
			Description: describeCapability(c),
			InputSchema: inputSchemaFor(c),
		})
	}
	return map[string]any{"tools": tools}, nil
}

// ---------------------------------------------------------------- tools/call

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// callContent membungkus hasil tools/call sesuai kontrak MCP: content
// text berisi JSON ringkas; isError=true untuk denial/error operasional.
type callContent struct {
	Content []map[string]any `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

func textContent(s string, isError bool) callContent {
	return callContent{
		Content: []map[string]any{{"type": "text", "text": s}},
		IsError: isError,
	}
}

// callResult membungkus status + field tambahan sebagai satu JSON text.
func callResult(status string, extra map[string]any, isError bool) callContent {
	m := map[string]any{"status": status}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return textContent(fmt.Sprintf("status=%s (marshal error: %v)", status, err), true)
	}
	return textContent(string(b), isError)
}

func (s *Server) toolsCall(params json.RawMessage) (any, *rpcError) {
	var p callParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, errInvalidParams("params tools/call tidak valid: " + err.Error())
		}
	}
	if strings.TrimSpace(p.Name) == "" {
		return nil, errInvalidParams("field 'name' wajib diisi")
	}
	// Allowlist: hanya capability terdaftar (§4.3). Unknown = invalid params.
	capDef, err := s.cfg.Registry.Resolve(p.Name)
	if err != nil {
		return nil, errInvalidParams(fmt.Sprintf("tool %q tidak ada di capability registry (fail-closed)", p.Name))
	}

	// §8: capability CRITICAL = disabled — selalu ditolak.
	if risk.Level(capDef.Risk) == risk.LevelCritical {
		s.auditDecision(p.Name, "denied", "capability critical = disabled (§8)", nil)
		return callResult("denied", map[string]any{
			"reason": fmt.Sprintf("capability %q ber-risk critical → disabled (§8): tidak pernah dieksekusi lewat control plane", p.Name),
		}, true), nil
	}

	// Read-only (tanpa network): stub informatif — dilayani control plane
	// tanpa menyentuh target (provider event store/docker menyusul).
	if !capDef.RequiresNetwork {
		s.auditDecision(p.Name, "stub", "read-only: tidak ada traffic ke target", nil)
		return callResult("stub", map[string]any{
			"capability": capDef.Name,
			"provider":   capDef.DefaultProvider,
			"note":       "read-only: hasil informatif; provider event-store/docker akan melayani capability ini di Phase 7/5 (ROADMAP 11/36)",
		}, false), nil
	}

	// Operasi aktif (requires_network): wajib url + method.
	urlStr, _ := p.Arguments["url"].(string)
	method, _ := p.Arguments["method"].(string)
	urlStr = strings.TrimSpace(urlStr)
	method = strings.ToUpper(strings.TrimSpace(method))
	if urlStr == "" || method == "" {
		return nil, errInvalidParams("arguments 'url' dan 'method' wajib string untuk capability requires_network")
	}
	caseID, _ := p.Arguments["case"].(string)
	caseID = strings.TrimSpace(caseID)

	// --- Policy check LOKAL, in-line (§4.3) — bukan saran, enforcement. ---

	// (1) Scope check — parser-based, fail-closed (§8).
	checker := s.cfg.Scope
	if checker == nil && s.cfg.ScopeFile != "" {
		allowed, err := s.loadAllowedHosts()
		if err != nil {
			s.auditDecision(p.Name, "denied", err.Error(), &urlStr)
			return callResult("denied", map[string]any{"reason": err.Error()}, true), nil
		}
		var err2 error
		checker, err2 = scope.NewChecker(allowed)
		if err2 != nil {
			s.auditDecision(p.Name, "denied", err2.Error(), &urlStr)
			return callResult("denied", map[string]any{"reason": err2.Error()}, true), nil
		}
	}
	if capDef.RequiresScope {
		if checker == nil {
			reason := "scope rules tidak tersedia (fail-closed): capability requires_scope tetapi --scope-file tidak dikonfigurasi"
			s.auditDecision(p.Name, "denied", reason, &urlStr)
			return callResult("denied", map[string]any{"reason": reason}, true), nil
		}
		if err := checker.Check(urlStr); err != nil {
			s.auditDecision(p.Name, "denied", err.Error(), &urlStr)
			return callResult("denied", map[string]any{
				"reason":   "scope: " + err.Error(),
				"sequence": "scope check gagal — operasi tidak pernah sampai ke provider",
			}, true), nil
		}
	}

	// (2) Kill switch: case yang di-abort tidak menerima eksekusi (§10).
	if caseID != "" && s.cfg.JobsDir != "" {
		if !jobs.ValidID(caseID) {
			reason := fmt.Sprintf("case id %q tidak valid (fail-closed)", caseID)
			s.auditDecision(p.Name, "denied", reason, &urlStr)
			return callResult("denied", map[string]any{"reason": reason}, true), nil
		}
		if jobs.IsAborted(s.cfg.JobsDir, caseID) {
			reason := fmt.Sprintf("case %q sudah di-abort (kill switch §10) — eksekusi ditolak", caseID)
			s.auditDecision(p.Name, "denied", reason, &urlStr)
			return callResult("denied", map[string]any{"reason": reason}, true), nil
		}
	}

	// (3) Risk classification + policy action (§8).
	level := risk.Classify(risk.Operation{Method: method, Replay: true})
	level, err = risk.MaxLevel(level, risk.Level(capDef.Risk))
	if err != nil {
		return nil, errInternal("risk level registry tidak valid: " + err.Error())
	}
	action, err := s.pol.Evaluate(capDef.Name, level)
	if err != nil {
		return nil, errInternal("policy evaluate: " + err.Error())
	}

	// (4) Action gate: automatic jalan; conditional/approval_required butuh
	// scoped approval aktif (§9); disabled ditolak (§8).
	switch action {
	case risk.ActionAutomatic:
		// lanjut ke dispatch di bawah.
	case risk.ActionConditional, risk.ActionApprovalRequired:
		// Approval ter-scope pada case (§9): argument 'case' wajib ada
		// dan harus match — tanpa itu tidak ada cara mem-validasi scope.
		if caseID == "" {
			denyReason := fmt.Sprintf("action=%s membutuhkan scoped approval (§9): argument 'case' wajib diisi agar approval dapat dipadankan dengan case engagement", action)
			s.auditDecision(p.Name, "denied", denyReason, &urlStr)
			return callResult("denied", map[string]any{
				"reason": denyReason, "risk": string(level), "action": string(action),
			}, true), nil
		}
		rec, denyReason := s.checkApproval(capDef, caseID, urlStr, method, action)
		if denyReason != "" {
			s.auditDecision(p.Name, "denied", denyReason, &urlStr)
			return callResult("denied", map[string]any{
				"reason": denyReason,
				"risk":   string(level),
				"action": string(action),
			}, true), nil
		}
		// Budget dikonsumsi hanya setelah semua check lolos.
		if err := s.cfg.Store.Consume(rec.ID); err != nil {
			reason := fmt.Sprintf("approval %s tidak bisa dikonsumsi: %v", rec.ID, err)
			s.auditDecision(p.Name, "denied", reason, &urlStr)
			return callResult("denied", map[string]any{"reason": reason}, true), nil
		}
	case risk.ActionDisabled:
		reason := fmt.Sprintf("policy action=disabled untuk risk=%s (§8) — ditolak", level)
		s.auditDecision(p.Name, "denied", reason, &urlStr)
		return callResult("denied", map[string]any{
			"reason": reason, "risk": string(level), "action": string(action),
		}, true), nil
	default:
		return nil, errInternal("policy action tidak dikenal: " + string(action))
	}

	// (5) Dispatch ke provider — hermes-proxy control channel (§11).
	body, _ := p.Arguments["body"].(string)
	headers, err := headersFromArgs(p.Arguments)
	if err != nil {
		return nil, errInvalidParams(err.Error())
	}
	proxyResp, err := s.forwardToProxy(urlStr, method, headers, body)
	if err != nil {
		s.auditDecision(p.Name, "error", err.Error(), &urlStr)
		return callResult("error", map[string]any{
			"reason": "provider (hermes-proxy) tidak dapat dihubungi: " + err.Error() +
				" — fail-closed, tidak ada fallback provider lain (§5.1)",
		}, true), nil
	}
	s.auditDecision(p.Name, "forwarded", "", &urlStr)
	return callResult("forwarded", map[string]any{
		"capability": capDef.Name,
		"provider":   capDef.DefaultProvider,
		"proxy":      proxyResp,
	}, false), nil
}

// checkApproval mencari scoped approval aktif untuk permintaan pada case.
// Return (record, "") bila ketemu; (nil, alasan) bila harus ditolak.
func (s *Server) checkApproval(capDef capability.Capability, caseID, rawURL, method string, action risk.Action) (*approval.Record, string) {
	if s.cfg.Store == nil {
		return nil, fmt.Sprintf("action=%s untuk risk operasi ini membutuhkan scoped approval (§8/§9), tetapi approval store tidak dikonfigurasi — fail-closed", action)
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, "URL tidak dapat di-parse untuk pencocokan approval: " + err.Error()
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	rec, err := s.cfg.Store.FindActive(capDef.Name, caseID, host, method, path)
	if err != nil {
		return nil, "approval store error: " + err.Error()
	}
	if rec == nil {
		return nil, fmt.Sprintf("action=%s: tidak ada scoped approval aktif untuk case=%s capability=%s method=%s host=%s path=%s (§9) — minta approval baru dari user, TIDAK ada silent renewal", action, caseID, capDef.Name, method, host, path)
	}
	return rec, ""
}

// headersFromArgs mengambil "headers" dari arguments (map dengan nilai
// string). Tipe salah = error (fail-closed, tanpa konversi senyap).
// Catatan: headers TIDAK PERNAH dicatat ke audit/log (bisa berisi
// Authorization/Cookie — §23).
func headersFromArgs(args map[string]any) (map[string]string, error) {
	raw, ok := args["headers"]
	if !ok || raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("argument 'headers' harus object string->string")
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("header %q harus bernilai string", k)
		}
		out[k] = s
	}
	return out, nil
}

// proxyRequest payload POST {proxy}/execute — dikirim apa adanya ke control
// channel hermes-proxy. headers/body di-omit bila kosong agar kompatibel
// dengan proxy yang ketat terhadap field tak dikenal (DisallowUnknownFields).
type proxyRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// forwardToProxy memanggil POST {ProxyURL}/execute. Response non-2xx dari
// proxy (policy in-line proxy menolak) diteruskan sebagai error — bukan
// fallback ke provider lain (§5.1).
func (s *Server) forwardToProxy(targetURL, method string, headers map[string]string, body string) (map[string]any, error) {
	payload, err := json.Marshal(proxyRequest{URL: targetURL, Method: method, Headers: headers, Body: body})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	endpoint := strings.TrimRight(s.cfg.ProxyURL, "/") + "/execute"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("response proxy tidak valid (http %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		reason, _ := out["reason"].(string)
		return out, fmt.Errorf("proxy menolak (http %d): %s", resp.StatusCode, reason)
	}
	return out, nil
}

// loadAllowedHosts membaca scope rules YAML {allowed_hosts} — format sama
// dengan validate-scope (internal/yamlmini, tanpa dependency).
func (s *Server) loadAllowedHosts() ([]string, error) {
	data, err := os.ReadFile(s.cfg.ScopeFile)
	if err != nil {
		return nil, fmt.Errorf("scope-file: baca %s: %w", s.cfg.ScopeFile, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("scope-file: parse %s: %w", s.cfg.ScopeFile, err)
	}
	raw, ok := doc["allowed_hosts"]
	if !ok {
		return nil, fmt.Errorf("scope-file: %s: field 'allowed_hosts' tidak ada", s.cfg.ScopeFile)
	}
	seq, ok := raw.([]any)
	if !ok || len(seq) == 0 {
		return nil, fmt.Errorf("scope-file: %s: 'allowed_hosts' harus seq tidak kosong", s.cfg.ScopeFile)
	}
	out := make([]string, 0, len(seq))
	for _, v := range seq {
		sv, ok := v.(string)
		if !ok || strings.TrimSpace(sv) == "" {
			return nil, fmt.Errorf("scope-file: %s: allowed_hosts harus berisi string", s.cfg.ScopeFile)
		}
		out = append(out, sv)
	}
	return out, nil
}

// auditDecision menulis audit entry keputusan tools/call. DISIPLIN (§23):
// headers, body, dan secret TIDAK PERNAH masuk audit — hanya method dan
// URL tanpa query (query bisa berisi token). Audit best-effort: keputusan
// enforcement tidak bergantung pada keberhasilan audit.
func (s *Server) auditDecision(tool, decision, reason string, rawURL *string) {
	if s.cfg.Audit == nil {
		return
	}
	detail := map[string]any{
		"tool":     tool,
		"decision": decision,
	}
	if reason != "" {
		detail["reason"] = reason
	}
	if rawURL != nil {
		detail["url"] = redactURL(*rawURL)
	}
	_ = s.cfg.Audit("mcp_tools_call", detail)
}

// redactURL membuang query dan fragment.
func redactURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "(unparseable)"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
