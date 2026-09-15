// Tool kontrol control plane — BUKAN capability (ROADMAP v3.0 §6):
//
//	security.validate_scope — cek URL terhadap scope rules, TANPA traffic.
//	security.run_validator  — jalankan validator terdaftar (image manifest
//	                          §21) di container Docker ephemeral via jobs +
//	                          dockerx (network=none §16, workspace §18).
//	security.abort_case     — kill switch §10: kill container ber-label case,
//	                          tulis ABORTED, revoke approval case.
//
// Semua handler menulis audit entry keputusan (§46) dan fail-closed:
// konfigurasi yang kurang (scope rules, manifest, jobs dir) = denial/error
// dengan pesan eksplisit — tidak ada silent degrade (§5.1).
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/dockerx"
	"hermes-security-skills/internal/jobs"
	"hermes-security-skills/internal/payload"
	"hermes-security-skills/internal/registry"
	"hermes-security-skills/internal/risk"
	"hermes-security-skills/internal/scope"
)

// defaultCaseID dipakai bila caller tidak menyertakan 'case' pada
// operasi yang butuh workspace (run_validator / tool run). Tetap
// tunduk kill-switch (jobs/<id>/ABORTED) sehingga bisa di-abort.
const defaultCaseID = "mcp-default"

// validatorRunTimeout timeout container validator (kalibrasi platform
// terlama, §15) — sama dengan default `hermes-security validate`.
const validatorRunTimeout = 60 * time.Second

// toolRunTimeout timeout container tool pihak ketiga (§15; budget presisi
// tetap dipaksa wrapper via policy bundle — §39).
const toolRunTimeout = 120 * time.Second

// validatorCmdArgs: flag default yang dikirim ke container validator.
// Image validator distroless memakai ENTRYPOINT (§13) dan konvensi path
// /workspace/{input,output} (§19), jadi Cmd hanya flag — bukan binary.
var validatorCmdArgs = []string{
	"--input", dockerx.ContainerInputDir + "/" + jobs.TaskFile,
	"--output", dockerx.ContainerOutputDir + "/" + jobs.ResultFile,
}

// mcpContainerName membangun nama container unik dan valid:
// hermes-mcp-<case>-<label>-<rand4>.
func mcpContainerName(caseID, label string) string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		copy(buf[:], "0000") // fallback deterministik (sangat jarang)
	}
	return "hermes-mcp-" + dockerx.SanitizeName(caseID) + "-" +
		dockerx.SanitizeName(label) + "-" + hex.EncodeToString(buf[:])
}

// caseArg mengambil case id dari arguments (opsional) — fail-closed:
// non-string / whitespace-only dikembalikan kosong (pemanggil memutus).
func caseArg(args map[string]any) string {
	s, _ := args["case"].(string)
	return strings.TrimSpace(s)
}

// effectiveCase menormalkan case id: arg caller atau defaultCaseID.
// Return kosong berarti arg bukan string valid (caller menolak).
func effectiveCase(args map[string]any) string {
	if c := caseArg(args); c != "" {
		return c
	}
	return defaultCaseID
}

// checkCaseSwitch memvalidasi case id + kill-switch abort (§10).
// Return "" = aman; selain itu alasan denial (sudah ter-audit).
func (s *Server) checkCaseSwitch(toolName, caseID string) string {
	if caseID == "" || s.cfg.JobsDir == "" {
		if s.cfg.JobsDir == "" {
			reason := "jobs-dir tidak dikonfigurasi (fail-closed): operasi ini butuh workspace + kill-switch abort (§10/§18)"
			s.auditDecision(toolName, "denied", reason, nil)
			return reason
		}
		reason := fmt.Sprintf("case id %q tidak valid (fail-closed)", caseID)
		s.auditDecision(toolName, "denied", reason, nil)
		return reason
	}
	if !jobs.ValidID(caseID) {
		reason := fmt.Sprintf("case id %q tidak valid (fail-closed)", caseID)
		s.auditDecision(toolName, "denied", reason, nil)
		return reason
	}
	if jobs.IsAborted(s.cfg.JobsDir, caseID) {
		reason := fmt.Sprintf("case %q sudah di-abort (kill switch §10) — eksekusi ditolak", caseID)
		s.auditDecision(toolName, "denied", reason, nil)
		return reason
	}
	return ""
}

// ---------------------------------------------------------------- select_payload

// callSelectPayload memilih payload yang telah divalidasi oleh internal/payload.
// Jalur ini read-only: tidak ada scope/network/Docker/proxy dispatch.
func (s *Server) callSelectPayload(p callParams) (any, *rpcError) {
	if s.cfg.PayloadRegistry == nil {
		reason := "payload registry tidak dikonfigurasi (fail-closed): selection membutuhkan registry tervalidasi"
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}
	if s.pol == nil || s.pol.Limits == nil {
		reason := "policy limits tidak tersedia (fail-closed): payload selection ditolak"
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}
	contextName, ok := p.Arguments["context"].(string)
	if !ok || strings.TrimSpace(contextName) == "" {
		return nil, errInvalidParams("argument 'context' wajib string non-empty")
	}
	rawRisk, ok := p.Arguments["risk"].(string)
	if !ok || strings.TrimSpace(rawRisk) == "" {
		return nil, errInvalidParams("argument 'risk' wajib string")
	}
	riskLevel := risk.Level(strings.ToLower(strings.TrimSpace(rawRisk)))
	if riskLevel == risk.LevelCritical {
		reason := "risk critical = disabled (§8): payload selection ditolak"
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason, "risk": string(riskLevel)}, true), nil
	}
	if _, err := risk.DefaultAction(riskLevel); err != nil {
		return nil, errInvalidParams("risk tidak valid: " + err.Error())
	}
	budget, ok := p.Arguments["budget"].(float64)
	if !ok || budget != float64(int(budget)) {
		return nil, errInvalidParams("argument 'budget' harus integer")
	}
	maxEntries := 0
	if raw, present := p.Arguments["max_entries"]; present {
		v, ok := raw.(float64)
		if !ok || v != float64(int(v)) {
			return nil, errInvalidParams("argument 'max_entries' harus integer")
		}
		maxEntries = int(v)
		if maxEntries < 1 {
			return nil, errInvalidParams("argument 'max_entries' harus integer >= 1")
		}
	}
	action, err := s.pol.Evaluate("select_payload", riskLevel)
	if err != nil {
		return nil, errInternal("policy evaluate: " + err.Error())
	}
	if action != risk.ActionAutomatic {
		reason := fmt.Sprintf("policy action=%s untuk risk=%s — payload selection ditolak fail-closed", action, riskLevel)
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason, "risk": string(riskLevel), "action": string(action)}, true), nil
	}
	selected, err := s.cfg.PayloadRegistry.Select(payload.Selection{
		Context: strings.TrimSpace(contextName), Risk: riskLevel,
		MaxEntries: maxEntries, Budget: int(budget),
	}, s.pol.Limits)
	if err != nil {
		s.auditDecision(p.Name, "denied", err.Error(), nil)
		return callResult("denied", map[string]any{"reason": err.Error()}, true), nil
	}
	s.auditDecision(p.Name, "selected", fmt.Sprintf("count=%d", len(selected)), nil)
	return callResult("selected", map[string]any{
		"provider": "payload", "context": strings.TrimSpace(contextName),
		"risk": string(riskLevel), "count": len(selected), "payloads": selected,
		"note": "payload tervalidasi saja; tidak dieksekusi atau dikirim",
	}, false), nil
}

// ---------------------------------------------------------------- validate_scope

// callValidateScope: security.validate_scope {url} — cek URL terhadap
// scope rules (--scope-file) TANPA traffic apa pun. Balas allowed/denied
// + reason. Fail-closed: scope rules tidak tersedia = denied (bukan allow).
func (s *Server) callValidateScope(p callParams) (any, *rpcError) {
	rawURL, _ := p.Arguments["url"].(string)
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errInvalidParams("argument 'url' wajib string (mis. https://host:port/path)")
	}
	checker := s.cfg.Scope
	if checker == nil && s.cfg.ScopeFile != "" {
		allowed, err := s.loadAllowedHosts()
		if err != nil {
			s.auditDecision(p.Name, "denied", err.Error(), &rawURL)
			return callResult("denied", map[string]any{"reason": err.Error()}, true), nil
		}
		c, err2 := scope.NewChecker(allowed)
		if err2 != nil {
			s.auditDecision(p.Name, "denied", err2.Error(), &rawURL)
			return callResult("denied", map[string]any{"reason": err2.Error()}, true), nil
		}
		checker = c
	}
	if checker == nil {
		reason := "scope rules tidak tersedia (fail-closed): jalankan serve dengan --scope-file"
		s.auditDecision(p.Name, "denied", reason, &rawURL)
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}
	if err := checker.Check(rawURL); err != nil {
		s.auditDecision(p.Name, "denied", err.Error(), &rawURL)
		return callResult("denied", map[string]any{
			"reason":   "scope: " + err.Error(),
			"sequence": "validate_scope — tidak ada traffic yang dikirim",
		}, true), nil
	}
	s.auditDecision(p.Name, "allowed", "", &rawURL)
	return callResult("allowed", map[string]any{
		"note": "URL dalam scope — pre-flight check saja, tidak ada traffic yang dikirim",
	}, false), nil
}

// --------------------------------------------------------------- run_validator

// callRunValidator: security.run_validator {validator_id, task, case?} —
// jalankan flow `validate` existing (jobs + dockerx) HANYA untuk validator
// yang terdaftar di image manifest (§21). Container network=none (§16),
// workspace jobs/<case>/<task> (§18), kill-switch aware (§10).
//
// Result validator adalah OBSERVATION — bukan finding final (§17/§22).
func (s *Server) callRunValidator(p callParams) (any, *rpcError) {
	validatorID, _ := p.Arguments["validator_id"].(string)
	validatorID = strings.TrimSpace(validatorID)
	if validatorID == "" {
		return nil, errInvalidParams("argument 'validator_id' wajib string (mis. http-response-comparison)")
	}
	task, ok := p.Arguments["task"].(map[string]any)
	if !ok {
		return nil, errInvalidParams("argument 'task' wajib object validation-task.json (§17)")
	}
	// Kontrak minimum task (§17): task_id + validator.id — dan validator.id
	// WAJIB sama dengan validator_id (fail-closed terhadap mismatch).
	taskID, _ := task["task_id"].(string)
	if strings.TrimSpace(taskID) == "" {
		return nil, errInvalidParams("task.task_id wajib string non-empty (§17)")
	}
	tv, ok := task["validator"].(map[string]any)
	if !ok {
		return nil, errInvalidParams("task.validator wajib object dengan field id (§17)")
	}
	taskValidatorID, _ := tv["id"].(string)
	if taskValidatorID != validatorID {
		return nil, errInvalidParams(fmt.Sprintf(
			"task.validator.id %q tidak cocok dengan validator_id %q (fail-closed)", taskValidatorID, validatorID))
	}
	caseID := effectiveCase(p.Arguments)

	// (1) Kill switch (§10) — case aborted tidak menerima task baru.
	if reason := s.checkCaseSwitch(p.Name, caseID); reason != "" {
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}

	// (2) Validator harus terdaftar di image manifest (§21) — fail-closed.
	if strings.TrimSpace(s.cfg.ManifestPath) == "" {
		reason := "manifest image tidak dikonfigurasi (fail-closed): jalankan serve dengan --manifest untuk mengaktifkan run_validator"
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}
	imageRef, err := resolveValidatorImage(s.cfg.ManifestPath, s.cfg.ImageOverridesPath, validatorID)
	if err != nil {
		s.auditDecision(p.Name, "denied", err.Error(), nil)
		return callResult("denied", map[string]any{
			"reason": fmt.Sprintf("validator %q tidak dapat di-resolve: %v (hanya validator terdaftar di manifest, §21)", validatorID, err),
		}, true), nil
	}

	// (3) Docker engine harus siap — pesan eksplisit (fail-closed).
	x := s.dockerExecer()
	if err := dockerx.AvailableWith(x); err != nil {
		s.auditDecision(p.Name, "error", err.Error(), nil)
		return callResult("error", map[string]any{"reason": err.Error()}, true), nil
	}

	// (4) Image harus sudah ada di daemon lokal — TIDAK ada pull otomatis.
	if ok, err := dockerx.ImageExistsWith(x, imageRef); err != nil {
		s.auditDecision(p.Name, "error", err.Error(), nil)
		return callResult("error", map[string]any{"reason": err.Error()}, true), nil
	} else if !ok {
		reason := fmt.Sprintf("image %s tidak ada di daemon lokal — build/pull dulu (tidak ada pull otomatis, §37)", imageRef)
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}

	// (5) Supply-chain verification wajib sebelum workspace atau container
	// dibuat. Validator source/tag dan manifest digest '-' ditolak fail-closed.
	if err := dockerx.VerifyImage(context.Background(), x, s.signatureVerifier(), dockerx.ImageVerificationSpec{
		Image: imageRef, SignatureRequired: true,
	}); err != nil {
		s.auditDecision(p.Name, "denied", err.Error(), nil)
		return callResult("denied", map[string]any{"reason": "validator image verification gagal: " + err.Error()}, true), nil
	}

	// (6) Workspace jobs (§18) + tulis task.
	jobsRoot, err := filepath.Abs(s.cfg.JobsDir)
	if err != nil {
		return nil, errInternal("resolve jobs-dir: " + err.Error())
	}
	ws, err := jobs.Create(jobsRoot, caseID, taskID)
	if err != nil {
		return nil, errInvalidParams(err.Error())
	}
	if err := ws.WriteTask(task); err != nil {
		return nil, errInternal(err.Error())
	}

	// (6) Eksekusi container ephemeral — baseline §15 + network=none §16.
	name := mcpContainerName(caseID, "val-"+validatorID)
	out, runErr := dockerx.RunWith(x, context.Background(), dockerx.RunSpec{
		Image:     imageRef,
		Cmd:       validatorCmdArgs,
		InputDir:  ws.InputDir,
		OutputDir: ws.OutputDir,
		Labels:    map[string]string{dockerx.LabelCase: caseID},
		Timeout:   validatorRunTimeout,
		Name:      name,
	})
	if logErr := ws.WriteLog("container.log", out); logErr != nil {
		s.logWarn("simpan log container: %v", logErr)
	}
	if runErr != nil {
		s.auditDecision(p.Name, "error", runErr.Error(), nil)
		return callResult("error", map[string]any{
			"reason":  runErr.Error(),
			"job_dir": filepath.ToSlash(ws.Dir),
		}, true), nil
	}

	// (7) Collect result (§18) — hilang = validator gagal menulis = error.
	result, err := ws.CollectResult()
	if err != nil {
		s.auditDecision(p.Name, "error", err.Error(), nil)
		return callResult("error", map[string]any{
			"reason":  err.Error(),
			"job_dir": filepath.ToSlash(ws.Dir),
		}, true), nil
	}
	status := ""
	if r, ok := result["result"].(map[string]any); ok {
		status, _ = r["status"].(string)
	}
	s.auditDecision(p.Name, "observed", "validator result status="+status, nil)
	return callResult("observed", map[string]any{
		"provider":  "docker",
		"validator": validatorID,
		"image":     imageRef,
		"case":      caseID,
		"result":    result,
		"job_dir":   filepath.ToSlash(ws.Dir),
		"note":      "result validator = observation, bukan finding final (§17/§22)",
	}, false), nil
}

// resolveValidatorImage menentukan image ref validator: override dev
// (§37) menang atas manifest; tanpa override, resolve via manifest (§21).
func resolveValidatorImage(manifestPath, overridesPath, validatorID string) (string, error) {
	if overridesPath != "" {
		ov, err := registry.LoadOverrides(overridesPath)
		if err != nil {
			return "", err
		}
		if ref, ok := registry.ApplyOverride(ov, validatorID); ok {
			return ref, nil
		}
	}
	m, err := registry.Load(manifestPath)
	if err != nil {
		return "", err
	}
	return m.Resolve(validatorID)
}

// ------------------------------------------------------------------ abort_case

// callAbortCase: security.abort_case {case} — kill switch manual satu case
// (§10) lewat jalur abort existing:
//
//	(a) kill container berlabel hermes.case=<case> (best-effort — Docker
//	    bermasalah TIDAK boleh mencegah marker + revoke);
//	(b) tulis jobs/<case>/ABORTED (fail-closed: gagal = abort gagal);
//	(c) revoke semua approval aktif case (revoked-by-abort, §9/§10);
//	(d) audit entry.
func (s *Server) callAbortCase(p callParams) (any, *rpcError) {
	caseID := caseArg(p.Arguments)
	if caseID == "" {
		return nil, errInvalidParams("argument 'case' wajib string (case id engagement)")
	}
	if !jobs.ValidID(caseID) {
		return nil, errInvalidParams(fmt.Sprintf("case id %q tidak valid (fail-closed)", caseID))
	}
	if strings.TrimSpace(s.cfg.JobsDir) == "" {
		reason := "jobs-dir tidak dikonfigurasi (fail-closed): abort butuh lokasi marker jobs/<case>/ABORTED"
		s.auditDecision(p.Name, "denied", reason, nil)
		return callResult("denied", map[string]any{"reason": reason}, true), nil
	}

	// (a) Kill container via label — best-effort.
	killed := 0
	var dockerErr error
	x := s.dockerExecer()
	if err := dockerx.AvailableWith(x); err != nil {
		dockerErr = fmt.Errorf("docker tidak tersedia: %w", err)
	} else {
		killed, dockerErr = dockerx.RemoveByLabelWith(x, dockerx.LabelCase+"="+caseID)
	}

	// (b) State marker — fail-closed.
	marker, err := jobs.MarkAborted(s.cfg.JobsDir, caseID)
	if err != nil {
		s.auditDecision(p.Name, "error", err.Error(), nil)
		return callResult("error", map[string]any{"reason": err.Error()}, true), nil
	}

	// (c) Revoke approval case (§9/§10). Store belum dikonfigurasi = 0
	//     revoked (tidak ada yang bisa dicabut) — bukan error.
	revokedN := 0
	var revokeErr error
	if s.cfg.Store != nil {
		revokedN, revokeErr = s.cfg.Store.RevokeCase(caseID, approval.ReasonRevokedByAbort)
	}

	detail := map[string]any{
		"case":              caseID,
		"containers_killed": killed,
		"marker":            filepath.ToSlash(marker),
		"approvals_revoked": revokedN,
	}
	if dockerErr != nil {
		detail["docker_warning"] = dockerErr.Error()
	}
	if revokeErr != nil {
		detail["revoke_warning"] = revokeErr.Error()
	}
	s.audit("aborted", detail)
	return callResult("aborted", detail, false), nil
}

// audit menulis satu audit entry langsung (untuk action di luar
// decisions tools/call standar).
func (s *Server) audit(action string, detail map[string]any) {
	if s.cfg.Audit == nil {
		return
	}
	_ = s.cfg.Audit(action, detail) //nolint:errcheck // audit best-effort
}

// logWarn mencatat peringatan ke stderr (log non-protokol).
func (s *Server) logWarn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "mcp: warning: "+format+"\n", args...)
}

// dockerExecer mengembalikan exec helper Docker yang dipakai control plane
// (TCB): injectable untuk test, CLI docker untuk produksi.
func (s *Server) dockerExecer() dockerx.Execer {
	if s.cfg.Docker != nil {
		return s.cfg.Docker
	}
	return dockerx.CLIExecer{}
}

func (s *Server) signatureVerifier() dockerx.SignatureVerifier {
	if s.cfg.SignatureVerifier != nil {
		return s.cfg.SignatureVerifier
	}
	return dockerx.CosignVerifier{
		KeyRef:                s.cfg.CosignKeyRef,
		CertificateIdentity:   s.cfg.CosignIdentity,
		CertificateOIDCIssuer: s.cfg.CosignIssuer,
	}
}
