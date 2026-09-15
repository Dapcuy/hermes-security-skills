// Eksekusi capability dengan provider "tool" (ROADMAP v3.0 §12/§36):
//
//	security.endpoint_discovery         -> subfinder / httpx / ffuf / nmap
//	security.template_based_validation  -> nuclei
//
// Alur (§6): schema validation -> scope check -> kill switch -> risk +
// approval gate per tool (Tool Registry §36 — approval requirement SPESIFIK
// PER TOOL ada di sana, bukan di capability; contoh nmap = "always") ->
// budget dari policy limits -> dockerx run image ter-pin (digest §40)
// ber-wrapper fail-closed (§39) -> validation-result.json -> MCP content.
//
// Tool output = observation/evidence — TIDAK PERNAH finding final (§17).
package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/capability"
	"hermes-security-skills/internal/dockerx"
	"hermes-security-skills/internal/jobs"
	"hermes-security-skills/internal/registry"
	"hermes-security-skills/internal/risk"
	"hermes-security-skills/internal/scope"
	"hermes-security-skills/internal/toolregistry"
)

// bundleFile / taskFile nama file kontrak di dalam input dir container.
const (
	toolBundleFile  = "bundle.json"
	toolTaskFile    = "validation-task.json"
	toolResultFile  = "validation-result.json"
	toolEnvBundleID = "POLICY_BUNDLE_SHA256"
)

// policyBundle bentuk policy bundle proxy yang dibaca wrapper (§11/§39).
type policyBundle struct {
	Version      int      `json:"version"`
	AllowedHosts []string `json:"allowed_hosts"`
	MaxRequests  int      `json:"max_requests"`
	RateLimitRPS int      `json:"rate_limit_rps"`
}

// scopeTarget menormalkan argumen target menjadi (URL untuk scope check,
// entry bundle allowed_hosts). Format diterima:
//
//	https?://host[:port][/path]  -> apa adanya
//	host:port                    -> https://host:port (scope) + host:port
//	host                         -> https://host (port default 443)
func scopeTarget(raw string) (scopeURL, bundleEntry string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("target kosong")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", "", fmt.Errorf("URL target tidak valid: %q", raw)
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		port := u.Port()
		if port == "" {
			switch u.Scheme {
			case "http":
				port = "80"
			case "https":
				port = "443"
			default:
				return "", "", fmt.Errorf("skema %q tidak didukung (http/https)", u.Scheme)
			}
		}
		return s, host + ":" + port, nil
	}
	// host:port atau host.
	if host, port, err := splitHostPort(s); err == nil && port != "" {
		return "https://" + host + ":" + port, host + ":" + port, nil
	}
	return "https://" + strings.TrimSuffix(s, "."), strings.TrimSuffix(strings.ToLower(s), "."), nil
}

// splitHostPort wrapper kecil agar net.SplitHostPort tidak diimpor hanya
// untuk satu pemakaian; error = bukan bentuk host:port.
func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", fmt.Errorf("bukan host:port")
	}
	host, port := s[:i], s[i+1:]
	if strings.Contains(host, ":") { // IPv6 tanpa bracket — tidak didukung argumen tool
		return "", "", fmt.Errorf("IPv6 harus bracket")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", "", fmt.Errorf("port bukan numerik")
		}
	}
	if host == "" || port == "" {
		return "", "", fmt.Errorf("host/port kosong")
	}
	return strings.ToLower(host), port, nil
}

// dispatchToolCapability mengeksekusi capability provider "tool" via Tool
// Registry + Docker runtime (ROADMAP v3.0 §36).
func (s *Server) dispatchToolCapability(capDef capability.Capability, internal string, p callParams) (any, *rpcError) {
	// (0) Tool Registry wajib — fail-closed.
	if s.cfg.ToolRegistry == nil {
		reason := "Tool Registry tidak dikonfigurasi (fail-closed): capability provider \"tool\" butuh tools/registry.yaml (§36) — jalankan serve dengan --tool-registry"
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}

	// (1) Resolusi tool: arg 'tool' wajib terdaftar dan melayani capability
	//     ini; tanpa arg, capability dengan TEPAT satu tool boleh
	//     melanjutkan (mis. template_based_validation -> nuclei).
	tools, err := s.cfg.ToolRegistry.ResolveByCapability(capDef.Name)
	if err != nil {
		s.auditDecision(p.Name, "denied", err.Error(), nil)
		return callResult("denied", map[string]any{"reason": err.Error()}, true), nil
	}
	toolName, _ := p.Arguments["tool"].(string)
	toolName = strings.TrimSpace(toolName)
	var tool toolregistry.Tool
	if toolName == "" {
		if len(tools) != 1 {
			names := make([]string, 0, len(tools))
			for _, t := range tools {
				names = append(names, t.Name)
			}
			return nil, errInvalidParams(fmt.Sprintf(
				"argument 'tool' wajib diisi untuk capability %q (tool terdaftar: %s)", capDef.Name, strings.Join(names, ", ")))
		}
		tool = tools[0]
	} else {
		t, rerr := s.cfg.ToolRegistry.Resolve(toolName)
		if rerr != nil {
			s.auditDecision(p.Name, "denied", rerr.Error(), nil)
			return callResult("denied", map[string]any{"reason": rerr.Error()}, true), nil
		}
		if t.Capability != capDef.Name {
			reason := fmt.Sprintf("tool %q melayani capability %q, bukan %q (fail-closed, §36)", toolName, t.Capability, capDef.Name)
			s.auditDecision(p.Name, "denied", reason, nil)
			return callResult("denied", map[string]any{"reason": reason}, true), nil
		}
		tool = t
	}

	// (2) Target: domain (subfinder) atau URL/host (httpx/ffuf/nuclei/nmap).
	domain, _ := p.Arguments["domain"].(string)
	domain = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(domain), "."))
	target, _ := p.Arguments["target"].(string)
	var scopeURL, bundleEntry string
	switch {
	case tool.Name == "subfinder":
		if domain == "" {
			return nil, errInvalidParams("argument 'domain' wajib string untuk tool subfinder (semantik -d)")
		}
		// Passive recon: tidak ada request ke target; domain wajib in-scope.
		scopeURL = "https://" + domain
		bundleEntry = domain
	default:
		if strings.TrimSpace(target) == "" {
			return nil, errInvalidParams(fmt.Sprintf("argument 'target' wajib string (URL/host in-scope) untuk tool %s", tool.Name))
		}
		scopeURL, bundleEntry, err = scopeTarget(target)
		if err != nil {
			return nil, errInvalidParams(err.Error())
		}
	}

	// (3) Scope check in-line (§8) — capability requires_scope.
	checker := s.cfg.Scope
	if checker == nil && s.cfg.ScopeFile != "" {
		allowed, err := s.loadAllowedHosts()
		if err != nil {
			s.auditDecision(p.Name, "denied", err.Error(), &scopeURL)
			return callResult("denied", map[string]any{"reason": err.Error()}, true), nil
		}
		c, err2 := scope.NewChecker(allowed)
		if err2 != nil {
			s.auditDecision(p.Name, "denied", err2.Error(), &scopeURL)
			return callResult("denied", map[string]any{"reason": err2.Error()}, true), nil
		}
		checker = c
	}
	if capDef.RequiresScope {
		if checker == nil {
			reason := "scope rules tidak tersedia (fail-closed): capability requires_scope tetapi --scope-file tidak dikonfigurasi"
			s.auditDecision(p.Name, "denied", reason, &scopeURL)
			return callResult("denied", map[string]any{"reason": reason}, true), nil
		}
		if err := checker.Check(scopeURL); err != nil {
			s.auditDecision(p.Name, "denied", err.Error(), &scopeURL)
			return callResult("denied", map[string]any{
				"reason":   "scope: " + err.Error(),
				"sequence": "scope check gagal — tool tidak pernah dieksekusi",
			}, true), nil
		}
	}

	// (4) Kill switch (§10).
	caseID := effectiveCase(p.Arguments)
	if reason := s.checkCaseSwitch(p.Name, caseID); reason != "" {
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}

	// (5) Risk check (§8): level = max(classifikasi operasi, risk
	//     capability, risk tool). Tool risk/approval spesifik per tool
	//     ditentukan Tool Registry (§36) — bukan capability.
	level := risk.Classify(risk.Operation{Method: "GET", Replay: true})
	for _, lv := range []string{capDef.Risk, tool.Risk} {
		l, err := risk.MaxLevel(level, risk.Level(lv))
		if err != nil {
			return nil, errInternal("risk level registry tidak valid: " + err.Error())
		}
		level = l
	}
	// The effective risk includes the tool-specific risk. A critical tool
	// must be disabled even when its capability is only medium/low; otherwise
	// registry metadata can bypass the global critical-action prohibition.
	if level == risk.LevelCritical {
		reason := fmt.Sprintf("risk efektif critical untuk tool %q = disabled (§8)", tool.Name)
		s.auditDecision(p.Name, "denied", reason, &scopeURL)
		return callResult("denied", map[string]any{
			"reason": reason,
			"tool":   tool.Name,
			"risk":   string(level),
		}, true), nil
	}

	// (6) Approval gate per tool.ApprovalRequirement (§12/§15/§36):
	//   automatic  -> jalan tanpa scoped approval;
	//   conditional -> wajib scoped approval aktif pada case;
	//   always     -> TIDAK PERNAH jalan tanpa scoped approval aktif.
	switch tool.ApprovalRequirement {
	case "automatic":
		// lanjut.
	case "conditional", "always":
		rec, denyReason := s.checkToolApproval(capDef, tool, caseID, scopeURL, risk.Action(tool.ApprovalRequirement))
		if denyReason != "" {
			s.auditDecision(p.Name, "denied", denyReason, &scopeURL)
			return callResult("denied", map[string]any{
				"reason":   denyReason,
				"tool":     tool.Name,
				"risk":     string(level),
				"approval": tool.ApprovalRequirement,
			}, true), nil
		}
		if err := s.cfg.Store.Consume(rec.ID); err != nil {
			reason := fmt.Sprintf("approval %s tidak bisa dikonsumsi: %v", rec.ID, err)
			s.auditDecision(p.Name, "denied", reason, &scopeURL)
			return callResult("denied", map[string]any{"reason": reason}, true), nil
		}
	default:
		return nil, errInternal("approval_requirement tool tidak dikenal: " + tool.ApprovalRequirement)
	}

	// (7) Budget bundle dari policy limits (ceiling §43) — wrapper yang
	//     menegakkan (§39); control plane tidak melewatkan nilai lebih besar.
	maxReq := s.pol.Limits.MaxRequestsTotal
	if maxReq <= 0 {
		maxReq = 1
	}
	bundle := policyBundle{
		Version:      1,
		AllowedHosts: []string{bundleEntry},
		MaxRequests:  maxReq,
		RateLimitRPS: s.pol.Limits.RateLimitRPS,
	}
	if bundle.RateLimitRPS <= 0 {
		bundle.RateLimitRPS = 1
	}
	bundleData, err := json.Marshal(bundle)
	if err != nil {
		return nil, errInternal("marshal bundle: " + err.Error())
	}
	sum := sha256.Sum256(bundleData)
	bundleSHA := hex.EncodeToString(sum[:])

	// (8) Workspace jobs (§18): input (bundle + validation-task) mount
	//     read-only; output untuk validation-result.json.
	jobsRoot, err := filepath.Abs(s.cfg.JobsDir)
	if err != nil {
		return nil, errInternal("resolve jobs-dir: " + err.Error())
	}
	taskID := uniqueTaskID("tool-" + tool.Name)
	ws, err := jobs.Create(jobsRoot, caseID, taskID)
	if err != nil {
		return nil, errInvalidParams(err.Error())
	}
	if err := os.WriteFile(filepath.Join(ws.InputDir, toolBundleFile), bundleData, 0o600); err != nil {
		return nil, errInternal("tulis bundle: " + err.Error())
	}
	taskDoc := map[string]any{
		"task_id":    taskID,
		"case":       caseID,
		"capability": capDef.Name,
		"tool":       tool.Name,
		"validator":  map[string]any{"id": "tool-" + tool.Name, "version": tool.Version},
		"target_scope": map[string]any{
			"bundle_entry": bundleEntry,
			"case":         caseID,
		},
	}
	if err := ws.WriteTask(taskDoc); err != nil {
		return nil, errInternal(err.Error())
	}

	// (9) Image ref: override dev (§37) menang, else digest pin (§40).
	imageRef := tool.Ref()
	if ref, ok := registry.ApplyOverride(s.cfg.ToolImageOverrides, tool.Name); ok {
		imageRef = ref
	} else if ref, ok := registry.ApplyOverride(s.cfg.ToolImageOverrides, tool.Image); ok {
		imageRef = ref
	}
	x := s.dockerExecer()
	if ok, err := dockerx.ImageExistsWith(x, imageRef); err != nil {
		s.auditDecision(p.Name, "error", err.Error(), nil)
		return callResult("error", map[string]any{"reason": err.Error()}, true), nil
	} else if !ok {
		reason := fmt.Sprintf("image %s tidak ada di daemon lokal — build/pull dulu (tidak ada pull otomatis, §37/§40)", imageRef)
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}
	if err := dockerx.VerifyImage(context.Background(), x, s.signatureVerifier(), dockerx.ImageVerificationSpec{
		Image:             imageRef,
		ExpectedDigest:    tool.Digest,
		SignatureRequired: tool.SignatureRequired,
	}); err != nil {
		s.auditDecision(p.Name, "denied", err.Error(), &scopeURL)
		return callResult("denied", map[string]any{"reason": err.Error(), "image": imageRef}, true), nil
	}

	// (10) Argumen per tool — whitelist SESUAI wrapper masing-masing image
	//      (§39). Tidak ada pass-through argumen mentah dari MCP args.
	cmd, err := toolWrapperCmd(tool, target, domain, p.Arguments)
	if err != nil {
		s.auditDecision(p.Name, "denied", err.Error(), &scopeURL)
		return callResult("denied", map[string]any{"reason": err.Error()}, true), nil
	}
	cmd = append([]string{"--bundle", dockerx.ContainerInputDir + "/" + toolBundleFile}, cmd...)

	// (11) Eksekusi container ephemeral — baseline §15; network bridge
	//      HANYA untuk tool ber-wrapper fail-closed (scope check per target
	//      ada di wrapper dari bundle, §39; egress via proxy = post-MVP §32).
	name := mcpContainerName(caseID, "tool-"+tool.Name)
	out, runErr := dockerx.RunWith(x, context.Background(), dockerx.RunSpec{
		Image:     imageRef,
		Cmd:       cmd,
		InputDir:  ws.InputDir,
		OutputDir: ws.OutputDir,
		Env:       []string{toolEnvBundleID + "=" + bundleSHA},
		Labels:    map[string]string{dockerx.LabelCase: caseID},
		Timeout:   toolRunTimeout,
		Name:      name,
		Network:   "bridge",
	})
	if logErr := ws.WriteLog("container.log", out); logErr != nil {
		s.logWarn("simpan log container: %v", logErr)
	}
	if runErr != nil {
		s.auditDecision(p.Name, "error", runErr.Error(), &scopeURL)
		return callResult("error", map[string]any{
			"reason":  runErr.Error(),
			"tool":    tool.Name,
			"image":   imageRef,
			"job_dir": filepath.ToSlash(ws.Dir),
		}, true), nil
	}

	// (12) Baca validation-result.json (§33) — hilang/invalid = error
	//      fail-closed (wrapper exit 0 tanpa output = kontrak rusak).
	resultData, err := os.ReadFile(filepath.Join(ws.OutputDir, toolResultFile))
	if err != nil {
		s.auditDecision(p.Name, "error", err.Error(), &scopeURL)
		return callResult("error", map[string]any{
			"reason":  err.Error(),
			"tool":    tool.Name,
			"job_dir": filepath.ToSlash(ws.Dir),
		}, true), nil
	}
	var result map[string]any
	if err := json.Unmarshal(resultData, &result); err != nil {
		s.auditDecision(p.Name, "error", "validation-result.json tidak valid: "+err.Error(), &scopeURL)
		return callResult("error", map[string]any{
			"reason":  "validation-result.json tidak valid: " + err.Error(),
			"tool":    tool.Name,
			"job_dir": filepath.ToSlash(ws.Dir),
		}, true), nil
	}

	s.auditDecision(p.Name, "observed", "tool="+tool.Name+" image="+imageRef, &scopeURL)
	return callResult("observed", map[string]any{
		"provider": "tool",
		"tool":     tool.Name,
		"version":  tool.Version,
		"image":    imageRef,
		"digest":   tool.Digest,
		"case":     caseID,
		"result":   result,
		"job_dir":  filepath.ToSlash(ws.Dir),
		"note":     "output tool = observation + provenance, bukan finding final (§17/§22)",
	}, false), nil
}

// checkToolApproval mencari scoped approval aktif untuk tool run pada case
// (§9). Approval di-scope pada (capability, case, host); path wildcard —
// tool wrapper yang membatasi target per request dari bundle.
func (s *Server) checkToolApproval(capDef capability.Capability, tool toolregistry.Tool, caseID, scopeURL string, want risk.Action) (*approval.Record, string) {
	if s.cfg.Store == nil {
		return nil, fmt.Sprintf("tool %q (approval_requirement=%s) membutuhkan scoped approval (§9/§36), tetapi approval store tidak dikonfigurasi — fail-closed", tool.Name, tool.ApprovalRequirement)
	}
	u, err := url.Parse(strings.TrimSpace(scopeURL))
	if err != nil {
		return nil, "URL tidak dapat di-parse untuk pencocokan approval: " + err.Error()
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	rec, err := s.cfg.Store.FindActive(capDef.Name, caseID, host, "GET", approval.PathAny)
	if err != nil {
		return nil, "approval store error: " + err.Error()
	}
	if rec == nil {
		return nil, fmt.Sprintf("tool %q (approval_requirement=%s): tidak ada scoped approval aktif untuk case=%s capability=%s host=%s (§9/§36) — minta approval baru dari user, TIDAK ada silent renewal", tool.Name, tool.ApprovalRequirement, caseID, capDef.Name, host)
	}
	return rec, ""
}

// toolWrapperCmd membangun argumen SETELAH --bundle sesuai whitelist
// wrapper tiap image (§39). Argumen tambahan (ports, wordlist) wajib
// sesuai kebutuhan tool — fail-closed, tanpa default diam-diam.
func toolWrapperCmd(tool toolregistry.Tool, target, domain string, args map[string]any) ([]string, error) {
	switch tool.Name {
	case "httpx":
		return []string{"-u", target}, nil
	case "subfinder":
		if domain == "" {
			return nil, fmt.Errorf("argument 'domain' wajib untuk subfinder")
		}
		return []string{"-d", domain}, nil
	case "nuclei":
		// Templates ter-bake ter-pin di image (default /nuclei-templates, §41)
		// — runtime tidak pernah auto-update.
		return []string{"--templates", "/nuclei-templates", target}, nil
	case "nmap":
		ports, _ := args["ports"].(string)
		ports = strings.TrimSpace(ports)
		if ports == "" {
			return nil, fmt.Errorf("argument 'ports' wajib string untuk tool nmap (wrapper menolak scan tanpa persetujuan port eksplisit)")
		}
		if strings.HasPrefix(ports, "-") || strings.ContainsAny(ports, " ;&|") {
			return nil, fmt.Errorf("argument 'ports' %q tidak valid", ports)
		}
		// Target nmap = host[:port] / host — buang skema bila URL diberikan.
		host := target
		if strings.Contains(host, "://") {
			u, err := url.Parse(host)
			if err != nil {
				return nil, fmt.Errorf("target %q tidak valid", target)
			}
			host = u.Host
		}
		return []string{"--ports", ports, host}, nil
	case "ffuf":
		wordlist, _ := args["wordlist"].(string)
		wordlist = strings.TrimSpace(wordlist)
		if wordlist == "" {
			return nil, fmt.Errorf("argument 'wordlist' wajib string untuk tool ffuf (path wordlist ter-bake di image; wrapper menolak fuzzing tanpa wordlist bake)")
		}
		if strings.Contains(wordlist, "..") || !strings.HasPrefix(wordlist, "/wordlists/") {
			return nil, fmt.Errorf("argument 'wordlist' %q harus path file ter-bake di bawah /wordlists/ (fail-closed, §13.1)", wordlist)
		}
		return []string{"-w", wordlist, "-u", target}, nil
	default:
		return nil, fmt.Errorf("tool %q belum punya pemetaan argumen wrapper (fail-closed)", tool.Name)
	}
}

// uniqueTaskID membuat task id valid jobs: <prefix>-<rand4> (charset
// aman §18; suffix acak mencegah output basi dari run sebelumnya).
func uniqueTaskID(prefix string) string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		copy(buf[:], "0000")
	}
	if len(prefix) > 48 {
		prefix = prefix[:48]
	}
	return prefix + "-" + hex.EncodeToString(buf[:])
}
