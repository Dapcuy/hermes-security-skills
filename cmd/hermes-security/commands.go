package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/audit"
	"hermes-security-skills/internal/capability"
	"hermes-security-skills/internal/dockerx"
	"hermes-security-skills/internal/jobs"
	"hermes-security-skills/internal/policy"
	"hermes-security-skills/internal/registry"
	"hermes-security-skills/internal/risk"
	"hermes-security-skills/internal/scope"
	"hermes-security-skills/internal/yamlmini"
)

// Default path relatif dari root repo.
const (
	defaultRegistry   = "capabilities/registry.yaml"
	defaultPolicyDir  = "policy"
	defaultSkillsDir  = "skills"
	defaultAuditFile  = "audit/audit.jsonl"
	validatorIdentity = "hermes-security/0.1.0"
)

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // pesan error dicetak oleh main
	return fs
}

func auditFlag(fs *flag.FlagSet) *string {
	return fs.String("audit-file", defaultAuditFile, "file audit JSONL (append-only, hash chain)")
}

// writeAudit membuka (atau membuat) file audit lalu menambah satu entry.
func writeAudit(path, action string, detail map[string]any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("audit: buat direktori %s: %w", dir, err)
		}
	}
	w, err := audit.Open(path)
	if err != nil {
		return err
	}
	_, err = w.Append(validatorIdentity, action, detail)
	return err
}

// ---------------------------------------------------------------- list-skills

type SkillInfo struct {
	Path        string // path SKILL.md (slash)
	Name        string
	Description string
	Version     string
	Risk        string
}

func cmdListSkills(args []string) error {
	fs := newFlagSet("list-skills")
	skillsDir := fs.String("skills-dir", defaultSkillsDir, "direktori skills")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	skills, err := ScanSkills(*skillsDir)
	if err != nil {
		return err
	}
	fmt.Printf("Skills (%d):\n", len(skills))
	for _, s := range skills {
		desc := s.Description
		if runes := []rune(desc); len(runes) > 72 {
			desc = string(runes[:72]) + "..."
		}
		fmt.Printf("  %-42s v%-6s risk=%-8s %s\n", s.Name, s.Version, s.Risk, desc)
	}
	return writeAudit(*auditFile, "list-skills", map[string]any{"count": len(skills)})
}

// ScanSkills mencari semua SKILL.md di bawah dir (rekursif) dan membaca
// frontmatter-nya. Fail-closed: satu SKILL.md tidak parseable = error.
func ScanSkills(dir string) ([]SkillInfo, error) {
	var out []SkillInfo
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "SKILL.md" {
			return nil
		}
		info, err := parseSkillFile(path)
		if err != nil {
			return err
		}
		out = append(out, info)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("skills: scan %s: %w", dir, walkErr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func parseSkillFile(path string) (SkillInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SkillInfo{}, fmt.Errorf("skills: baca %s: %w", path, err)
	}
	fm, err := parseFrontmatter(data)
	if err != nil {
		return SkillInfo{}, fmt.Errorf("skills: %s: %w", path, err)
	}
	info := SkillInfo{Path: filepath.ToSlash(path)}
	if info.Name, err = fmRequired(fm, "name", path); err != nil {
		return SkillInfo{}, err
	}
	if info.Version, err = fmRequired(fm, "version", path); err != nil {
		return SkillInfo{}, err
	}
	if info.Risk, err = fmRequired(fm, "risk", path); err != nil {
		return SkillInfo{}, err
	}
	info.Description = fm["description"]
	return info, nil
}

// parseFrontmatter membaca frontmatter sederhana "key: value" di antara dua
// baris "---". Mendukung nilai quoted dan blok multiline ('>' / '|') yang
// dilipat menjadi satu string dengan spasi.
func parseFrontmatter(data []byte) (map[string]string, error) {
	lines := strings.Split(string(data), "\n")
	i := 0
	for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
		i++
	}
	if i >= len(lines) || strings.TrimSpace(lines[i]) != "---" {
		return nil, fmt.Errorf("frontmatter tidak ditemukan (harus mulai dengan '---')")
	}
	i++
	fm := map[string]string{}
	curKey := ""
	var parts []string
	closed := false
	for ; i < len(lines); i++ {
		raw := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "---" {
			closed = true
			break
		}
		if trimmed == "" {
			continue
		}
		if curKey != "" && (raw[0] == ' ' || raw[0] == '\t') {
			// Lanjutan blok multiline untuk key sebelumnya.
			parts = append(parts, trimmed)
			continue
		}
		if curKey != "" {
			fm[curKey] = strings.TrimSpace(strings.Join(parts, " "))
			curKey = ""
			parts = nil
		}
		key, rest, ok := splitKeyValue(trimmed)
		if !ok {
			return nil, fmt.Errorf("baris frontmatter tidak valid: %q", trimmed)
		}
		if rest == ">" || rest == "|" || rest == ">-" || rest == "|-" {
			curKey = key // mulai blok multiline
			continue
		}
		fm[key] = unquoteYAMLValue(rest)
	}
	if !closed {
		return nil, fmt.Errorf("frontmatter tidak ditutup dengan '---'")
	}
	if curKey != "" {
		fm[curKey] = strings.TrimSpace(strings.Join(parts, " "))
	}
	return fm, nil
}

func splitKeyValue(s string) (key, rest string, ok bool) {
	idx := strings.Index(s, ":")
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), true
}

func unquoteYAMLValue(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func fmRequired(fm map[string]string, key, path string) (string, error) {
	v, ok := fm[key]
	if !ok || strings.TrimSpace(v) == "" {
		return "", fmt.Errorf("skills: %s: frontmatter %q wajib ada", path, key)
	}
	return v, nil
}

// ---------------------------------------------------------------- route

type RankedSkill struct {
	Skill SkillInfo
	Score int
}

// RouteSkills: stub routing sederhana — skor = jumlah kata query yang
// muncul di nama + deskripsi skill (lowercase). Skill tanpa skor dihilangkan.
func RouteSkills(query string, skills []SkillInfo) []RankedSkill {
	tokens := strings.Fields(strings.ToLower(strings.TrimSpace(query)))
	var out []RankedSkill
	for _, s := range skills {
		hay := strings.ToLower(s.Name + " " + s.Description)
		score := 0
		for _, tk := range tokens {
			if strings.Contains(hay, tk) {
				score++
			}
		}
		if score > 0 {
			out = append(out, RankedSkill{Skill: s, Score: score})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Skill.Name < out[j].Skill.Name
	})
	return out
}

func cmdRoute(args []string) error {
	fs := newFlagSet("route")
	query := fs.String("query", "", "teks konteks task")
	skillsDir := fs.String("skills-dir", defaultSkillsDir, "direktori skills")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*query) == "" {
		return fmt.Errorf("route: --query wajib diisi")
	}
	skills, err := ScanSkills(*skillsDir)
	if err != nil {
		return err
	}
	ranked := RouteSkills(*query, skills)
	// Kejujuran output (§4.2 advisory): hasil ini datang dari stub sederhana,
	// bukan router penuh. Jangan disajikan seolah routing semantik.
	fmt.Println("route: STUB sederhana (match kata kunci query pada nama + deskripsi skill, tanpa semantik/konteks).")
	fmt.Println("       Routing penuh = ROUTING.md — hasil di bawah hanya kandidat kasar untuk review user.")
	if len(ranked) == 0 {
		fmt.Println("route: tidak ada skill yang cocok")
	} else {
		fmt.Printf("Route untuk %q (%d kandidat):\n", *query, len(ranked))
		for _, r := range ranked {
			fmt.Printf("  skor=%d %s\n", r.Score, r.Skill.Name)
		}
	}
	return writeAudit(*auditFile, "route", map[string]any{"query": *query, "matches": len(ranked)})
}

// ------------------------------------------------------- list-capabilities

func cmdListCapabilities(args []string) error {
	fs := newFlagSet("list-capabilities")
	registry := fs.String("registry", defaultRegistry, "path capability registry YAML")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg, err := capability.Load(*registry)
	if err != nil {
		return err
	}
	fmt.Printf("Capabilities (%d) dari %s:\n", reg.Count(), *registry)
	for _, c := range reg.List() {
		fmt.Printf("  %-28s risk=%-8s provider=%-8s scope=%-5v network=%-5v approval=%s\n",
			c.Name, c.Risk, c.DefaultProvider, c.RequiresScope, c.RequiresNetwork, c.RequiresApproval)
	}
	return writeAudit(*auditFile, "list-capabilities", map[string]any{"count": reg.Count()})
}

// ---------------------------------------------------------- validate-scope

func cmdValidateScope(args []string) error {
	fs := newFlagSet("validate-scope")
	urlFlag := fs.String("url", "", "URL yang divalidasi")
	scopeFile := fs.String("scope-file", "", "scope rules YAML {allowed_hosts: [...]}")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *urlFlag == "" {
		return fmt.Errorf("validate-scope: --url wajib diisi")
	}
	if *scopeFile == "" {
		return fmt.Errorf("validate-scope: --scope-file wajib diisi")
	}
	allowed, err := loadAllowedHosts(*scopeFile)
	if err != nil {
		return err
	}
	if err := scope.Validate(*urlFlag, allowed); err != nil {
		// Tolak tetap ter-audit, lalu error ke caller (exit 1).
		if auditErr := writeAudit(*auditFile, "validate-scope", map[string]any{
			"url": *urlFlag, "result": "denied", "reason": err.Error(),
		}); auditErr != nil {
			return auditErr
		}
		return err
	}
	fmt.Printf("OK: %s dalam scope (%d host di-allowlist)\n", *urlFlag, len(allowed))
	return writeAudit(*auditFile, "validate-scope", map[string]any{"url": *urlFlag, "result": "allowed"})
}

// loadAllowedHosts membaca scope rules YAML sederhana {allowed_hosts: [...]}.
func loadAllowedHosts(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scope-file: baca %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("scope-file: parse %s: %w", path, err)
	}
	raw, ok := doc["allowed_hosts"]
	if !ok {
		return nil, fmt.Errorf("scope-file: %s: field 'allowed_hosts' tidak ada", path)
	}
	seq, ok := raw.([]any)
	if !ok || len(seq) == 0 {
		return nil, fmt.Errorf("scope-file: %s: 'allowed_hosts' harus seq tidak kosong", path)
	}
	out := make([]string, 0, len(seq))
	for _, v := range seq {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("scope-file: %s: allowed_hosts harus berisi string", path)
		}
		out = append(out, s)
	}
	return out, nil
}

// ------------------------------------------------------------ check-policy

type PolicyDecision struct {
	Capability string
	Method     string
	Risk       risk.Level
	Action     risk.Action
}

// CheckPolicy: klasifikasi risk operasi (via internal/risk), ambil level
// tertinggi dibanding risk capability dari registry (konservatif),
// lalu evaluasi action (via internal/policy). Fail-closed.
func CheckPolicy(registryPath, policyDir, capabilityName, method string) (PolicyDecision, error) {
	if capabilityName == "" {
		return PolicyDecision{}, fmt.Errorf("check-policy: --capability wajib diisi")
	}
	reg, err := capability.Load(registryPath)
	if err != nil {
		return PolicyDecision{}, err
	}
	capDef, err := reg.Resolve(capabilityName)
	if err != nil {
		return PolicyDecision{}, err
	}
	methodLevel := risk.Classify(risk.Operation{Method: method})
	registryLevel := risk.Level(capDef.Risk)
	level, err := risk.MaxLevel(methodLevel, registryLevel)
	if err != nil {
		return PolicyDecision{}, err
	}
	pol, err := policy.Load(policyDir)
	if err != nil {
		return PolicyDecision{}, err
	}
	action, err := pol.Evaluate(capabilityName, level)
	if err != nil {
		return PolicyDecision{}, err
	}
	return PolicyDecision{
		Capability: capabilityName,
		Method:     method,
		Risk:       level,
		Action:     action,
	}, nil
}

func cmdCheckPolicy(args []string) error {
	fs := newFlagSet("check-policy")
	capName := fs.String("capability", "", "nama capability")
	method := fs.String("method", "", "HTTP method operasi (kosong untuk operasi non-HTTP)")
	registry := fs.String("registry", defaultRegistry, "path capability registry YAML")
	policyDir := fs.String("policy-dir", defaultPolicyDir, "direktori policy")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	dec, err := CheckPolicy(*registry, *policyDir, *capName, *method)
	if err != nil {
		return err
	}
	fmt.Printf("capability=%s method=%s risk=%s action=%s\n",
		dec.Capability, dec.Method, dec.Risk, dec.Action)
	return writeAudit(*auditFile, "check-policy", map[string]any{
		"capability": dec.Capability, "method": dec.Method,
		"risk": string(dec.Risk), "action": string(dec.Action),
	})
}

// ---------------------------------------------------------------- doctor

type DoctorCheck struct {
	Name   string
	OK     bool
	Detail string
}

// RunDoctor menjalankan pemeriksaan kesehatan project:
// registry parseable, policy files ada, skills terbaca.
func RunDoctor(registryPath, policyDir, skillsDir string) ([]DoctorCheck, error) {
	var out []DoctorCheck
	add := func(name string, ok bool, detail string) {
		out = append(out, DoctorCheck{Name: name, OK: ok, Detail: detail})
	}

	// 1. Capability registry ada & parseable & tidak kosong.
	reg, err := capability.Load(registryPath)
	switch {
	case err != nil:
		add("registry", false, err.Error())
	case reg.Count() == 0:
		add("registry", false, fmt.Sprintf("%s: tidak ada capability", registryPath))
	default:
		add("registry", true, fmt.Sprintf("%s: %d capability", registryPath, reg.Count()))
	}

	// 2. policy/risk.yaml parseable.
	if _, err := policy.LoadRisk(filepath.Join(policyDir, "risk.yaml")); err != nil {
		add("policy-risk", false, err.Error())
	} else {
		add("policy-risk", true, filepath.Join(policyDir, "risk.yaml")+" ok")
	}

	// 3. policy/limits.yaml parseable.
	if _, err := policy.LoadLimits(filepath.Join(policyDir, "limits.yaml")); err != nil {
		add("policy-limits", false, err.Error())
	} else {
		add("policy-limits", true, filepath.Join(policyDir, "limits.yaml")+" ok")
	}

	// 4. Skills terbaca; minimal satu skill.
	skills, err := ScanSkills(skillsDir)
	if err != nil {
		add("skills", false, err.Error())
	} else if len(skills) == 0 {
		add("skills", false, fmt.Sprintf("%s: tidak ada SKILL.md", skillsDir))
	} else {
		add("skills", true, fmt.Sprintf("%s: %d skill", skillsDir, len(skills)))
	}
	return out, nil
}

func cmdDoctor(args []string) error {
	fs := newFlagSet("doctor")
	registry := fs.String("registry", defaultRegistry, "path capability registry YAML")
	policyDir := fs.String("policy-dir", defaultPolicyDir, "direktori policy")
	skillsDir := fs.String("skills-dir", defaultSkillsDir, "direktori skills")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	checks, err := RunDoctor(*registry, *policyDir, *skillsDir)
	if err != nil {
		return err
	}
	failed := 0
	fmt.Println("doctor:")
	for _, c := range checks {
		status := "OK  "
		if !c.OK {
			status = "FAIL"
			failed++
		}
		fmt.Printf("  [%s] %-14s %s\n", status, c.Name, c.Detail)
	}
	if auditErr := writeAudit(*auditFile, "doctor", map[string]any{
		"checks": len(checks), "failed": failed,
	}); auditErr != nil {
		return auditErr
	}
	if failed > 0 {
		return fmt.Errorf("doctor: %d check gagal", failed)
	}
	return nil
}

// ---------------------------------------------------------------- validate

// Default Phase 5 (ROADMAP §36).
const (
	defaultManifest          = "runtimes/proxy/manifests/image-manifest.yaml"
	defaultJobsDir           = "jobs"
	defaultEvidenceDir       = "jobs/evidence" // default sama dengan hermes-proxy --evidence-dir
	defaultValidationTimeout = 60 * time.Second
	supportedRuntime         = "docker"
)

// validatorCmdArgs: flag default yang dikirim ke container. Image validator
// distroless (§13) sudah memuat ENTRYPOINT binary validator dan mengikuti
// konvensi path /workspace/{input,output} (§19), jadi Cmd hanya flag —
// bukan binary+flag (mengirim binary lagi akan dobel dengan ENTRYPOINT).
var validatorCmdArgs = []string{
	"--input", dockerx.ContainerInputDir + "/" + jobs.TaskFile,
	"--output", dockerx.ContainerOutputDir + "/" + jobs.ResultFile,
}

// containerName membangun nama container unik dan valid:
// hermes-val-<case>-<task>-<rand4>. Charset dibatasi via dockerx.SanitizeName;
// suffix acak mencegah bentrok dengan sisa container lama.
func containerName(caseID, taskID string) string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		copy(buf[:], "0000") // fallback deterministik (sangat jarang)
	}
	return "hermes-val-" + dockerx.SanitizeName(caseID) + "-" +
		dockerx.SanitizeName(taskID) + "-" + hex.EncodeToString(buf[:])
}

// loadValidationTask membaca validation-task.json (§17) dan mengambil field
// kontrak minimum (task_id, validator.id). Fail-closed: JSON tidak valid,
// field wajib hilang = error.
func loadValidationTask(path string) (map[string]any, string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", "", fmt.Errorf("validate: baca task %s: %w", path, err)
	}
	var task map[string]any
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, "", "", fmt.Errorf("validate: parse task %s: %w", path, err)
	}
	taskID, ok := stringField(task, "task_id")
	if !ok || taskID == "" {
		return nil, "", "", fmt.Errorf("validate: %s: task_id wajib string non-empty (§17)", path)
	}
	validator, ok := task["validator"].(map[string]any)
	if !ok {
		return nil, "", "", fmt.Errorf("validate: %s: field 'validator' wajib object (§17)", path)
	}
	validatorID, ok := stringField(validator, "id")
	if !ok || validatorID == "" {
		return nil, "", "", fmt.Errorf("validate: %s: validator.id wajib string non-empty (§17)", path)
	}
	return task, validatorID, taskID, nil
}

func stringField(m map[string]any, key string) (string, bool) {
	v, ok := m[key].(string)
	return v, ok
}

// resolveImage menentukan image ref: override dev (jalur build-from-source,
// §37) menang atas manifest; tanpa override, resolve via manifest registry
// (§21). Image tidak dikenal = error fail-closed.
func resolveImage(manifestPath, overridesPath, validatorID string) (string, error) {
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

// printValidationResult menampilkan ringkasan validation-result.json.
// Status result adalah OBSERVATION — bukan keputusan vulnerability (§17).
func printValidationResult(result map[string]any, imageRef, container, jobDir string) {
	status := ""
	if r, ok := result["result"].(map[string]any); ok {
		status, _ = r["status"].(string)
	}
	taskID, _ := result["task_id"].(string)
	validatorID, version := "", ""
	if v, ok := result["validator"].(map[string]any); ok {
		validatorID, _ = v["id"].(string)
		version, _ = v["version"].(string)
	}
	fmt.Println("validate: selesai")
	fmt.Printf("  task        : %s\n", taskID)
	fmt.Printf("  validator   : %s v%s\n", validatorID, version)
	fmt.Printf("  image       : %s\n", imageRef)
	fmt.Printf("  container   : %s (ephemeral, --rm — sudah dihancurkan)\n", container)
	fmt.Printf("  result      : %s\n", status)
	if obs, ok := result["observations"].([]any); ok {
		fmt.Printf("  observations: %d\n", len(obs))
		for i, o := range obs {
			if i >= 10 {
				fmt.Printf("    ... (%d lagi)\n", len(obs)-i)
				break
			}
			if m, ok := o.(map[string]any); ok {
				typ, _ := m["type"].(string)
				detail, _ := m["detail"].(string)
				fmt.Printf("    - [%s] %s\n", typ, detail)
			}
		}
	}
	fmt.Printf("  job dir     : %s\n", filepath.ToSlash(jobDir))
}

// cmdValidate menjalankan satu validation task di container Docker ephemeral
// (Phase 5, ROADMAP §36):
//
//	task JSON → resolve image (manifest registry, §21) → workspace jobs (§18)
//	→ dockerx.Run (baseline §15 + network=none §16) → collect result → audit.
//
// Fail-closed di semua titik: docker tidak tersedia = error jelas, image
// tidak dikenal/missing = error, case aborted = ditolak (§10).
func cmdValidate(args []string) error {
	fs := newFlagSet("validate")
	runtimeName := fs.String("runtime", "docker", "runtime eksekusi (hanya 'docker' — validator network=none, §16)")
	taskPath := fs.String("task", "", "path validation-task.json (wajib)")
	caseID := fs.String("case", "", "case id: label hermes.case + workspace jobs/<case> (wajib)")
	jobsDirFlag := fs.String("jobs-dir", defaultJobsDir, "root direktori jobs workspace (§18)")
	manifestPath := fs.String("manifest", defaultManifest, "path image manifest YAML (§13)")
	overridesPath := fs.String("image-overrides", "", "opsional: file YAML override image dev (validator-id: image-ref)")
	timeout := fs.Duration("timeout", defaultValidationTimeout, "timeout container (kalibrasi platform terlama, §15)")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *runtimeName != supportedRuntime {
		return fmt.Errorf("validate: runtime %q tidak didukung (hanya %q; tidak ada silent degrade, §5.1)", *runtimeName, supportedRuntime)
	}
	if strings.TrimSpace(*taskPath) == "" {
		return fmt.Errorf("validate: --task wajib diisi")
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("validate: --case wajib diisi")
	}

	// 1) Docker engine harus siap — pesan error eksplisit (fail-closed).
	if err := dockerx.Available(); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	// 2) Load task + cek kontrak minimum (§17).
	task, validatorID, taskID, err := loadValidationTask(*taskPath)
	if err != nil {
		return err
	}

	// 3) Kill switch: case yang di-abort tidak menerima task baru (§10).
	// Jobs root di-resolve absolut: bind mount dockerx wajib path absolut
	// (fail-closed buildRunArgs), sementara default --jobs-dir relatif CWD.
	jobsRoot, err := filepath.Abs(*jobsDirFlag)
	if err != nil {
		return fmt.Errorf("validate: resolve jobs-dir: %w", err)
	}
	if jobs.IsAborted(jobsRoot, *caseID) {
		return fmt.Errorf("validate: case %q sudah di-abort (%s) — case dihentikan, task baru ditolak", *caseID, filepath.ToSlash(filepath.Join(jobsRoot, *caseID, jobs.AbortedFile)))
	}

	// 4) Resolve image dari manifest registry (override dev menang).
	imageRef, err := resolveImage(*manifestPath, *overridesPath, validatorID)
	if err != nil {
		return fmt.Errorf("validate: resolve image untuk validator %q: %w", validatorID, err)
	}

	// 5) Image harus sudah ada di daemon lokal — TIDAK ada pull otomatis;
	//    registry + verifikasi signature baru masuk Phase 6/7 (§37).
	ok, err := dockerx.ImageExists(imageRef)
	if err != nil {
		return fmt.Errorf("validate: cek image %s: %w", imageRef, err)
	}
	if !ok {
		return fmt.Errorf("validate: image %s tidak ada di daemon lokal — build/pull dulu (mis. docker build -f runtimes/docker/images/http-validator/Dockerfile -t %s .) atau pakai --image-overrides", imageRef, imageRef)
	}

	// 6) Workspace job (§18): jobs/<case>/<task>/{input,output,artifacts,logs}.
	ws, err := jobs.Create(jobsRoot, *caseID, taskID)
	if err != nil {
		return err
	}
	if err := ws.WriteTask(task); err != nil {
		return err
	}

	// 7) Eksekusi container ephemeral — baseline §15 + network=none §16
	//    ditetapkan oleh adapter (bukan oleh input Hermes mana pun).
	name := containerName(*caseID, taskID)
	out, err := dockerx.Run(context.Background(), dockerx.RunSpec{
		Image:     imageRef,
		Cmd:       validatorCmdArgs,
		InputDir:  ws.InputDir,
		OutputDir: ws.OutputDir,
		Labels:    map[string]string{dockerx.LabelCase: *caseID},
		Timeout:   *timeout,
		Name:      name,
	})
	// Log container selalu disimpan, sukses maupun gagal (bukti eksekusi §18).
	if logErr := ws.WriteLog("container.log", out); logErr != nil {
		fmt.Fprintf(os.Stderr, "validate: peringatan simpan log: %v\n", logErr)
	}
	if err != nil {
		if auditErr := writeAudit(*auditFile, "validate", map[string]any{
			"case": *caseID, "task_id": taskID, "validator": validatorID,
			"image": imageRef, "container": name, "runtime": supportedRuntime,
			"result": "error", "error": err.Error(),
			"job_dir": filepath.ToSlash(ws.Dir),
		}); auditErr != nil {
			return auditErr
		}
		return fmt.Errorf("validate: %w (log container: %s)", err, filepath.ToSlash(ws.ContainerLogPath()))
	}

	// 8) Collect result (§18). Hilang = validator gagal menulis = error.
	result, err := ws.CollectResult()
	if err != nil {
		if auditErr := writeAudit(*auditFile, "validate", map[string]any{
			"case": *caseID, "task_id": taskID, "validator": validatorID,
			"image": imageRef, "container": name, "runtime": supportedRuntime,
			"result": "error", "error": err.Error(),
			"job_dir": filepath.ToSlash(ws.Dir),
		}); auditErr != nil {
			return auditErr
		}
		return fmt.Errorf("validate: %w (log container: %s)", err, filepath.ToSlash(ws.ContainerLogPath()))
	}

	// 9) Tampilkan hasil (observation, bukan keputusan — §17) + audit.
	printValidationResult(result, imageRef, name, ws.Dir)
	status := ""
	if r, ok := result["result"].(map[string]any); ok {
		status, _ = r["status"].(string)
	}
	obsCount := 0
	if obs, ok := result["observations"].([]any); ok {
		obsCount = len(obs)
	}
	return writeAudit(*auditFile, "validate", map[string]any{
		"case": *caseID, "task_id": taskID, "validator": validatorID,
		"image": imageRef, "container": name, "runtime": supportedRuntime,
		"result": status, "observations": obsCount,
		"job_dir": filepath.ToSlash(ws.Dir),
	})
}

// ---------------------------------------------------------------- abort

// cmdAbort kill switch manual satu case (ROADMAP §10):
//
//	(a) kill semua container berlabel hermes.case=<id> (validator DAN
//	    hermes-proxy — keduanya memakai label case yang sama);
//	(b) tulis state file jobs/<case>/ABORTED — task baru untuk case ini
//	    ditolak fail-closed oleh cmdValidate;
//	(c) revoke SEMUA approval aktif untuk case di approval store
//	    (reason "revoked-by-abort") — §9/§10;
//	(d) tulis audit entry "aborted" (+ jumlah approval dicabut);
//	(e) print ringkasan.
func cmdAbort(args []string) error {
	fs := newFlagSet("abort")
	caseID := fs.String("case", "", "case id yang di-abort")
	jobsDirFlag := fs.String("jobs-dir", defaultJobsDir, "root direktori jobs")
	stateDirFlag := fs.String("state-dir", defaultJobsDir, "direktori state approval store (approvals.json)")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("abort: --case wajib diisi")
	}

	// (a) Kill container via label. Docker bermasalah tidak boleh mencegah
	//     marker+audit — tapi abort yang parsial tetap dilaporkan error.
	killed := 0
	var dockerErr error
	if err := dockerx.Available(); err != nil {
		dockerErr = fmt.Errorf("docker tidak tersedia: %w", err)
	} else {
		killed, dockerErr = dockerx.RemoveByLabel(dockerx.LabelCase + "=" + *caseID)
	}

	// (b) State file — fail-closed: gagal tulis marker = abort gagal total.
	marker, err := jobs.MarkAborted(*jobsDirFlag, *caseID)
	if err != nil {
		return err
	}

	// (c) Revoke semua approval case (§9/§10). Store belum ada = 0 revoked
	//     (bukan error — memang tidak ada approval); store korup = warning
	//     yang dilaporkan, tidak boleh meyembunyikan abort.
	store := approval.OpenStore(filepath.Join(*stateDirFlag, "approvals.json"))
	revokedN, revokeErr := store.RevokeCase(*caseID, approval.ReasonRevokedByAbort)

	// (d) Audit entry (chain tamper-evident, §25).
	detail := map[string]any{
		"case":              *caseID,
		"containers_killed": killed,
		"marker":            filepath.ToSlash(marker),
		"approvals_revoked": revokedN,
		"approval_store":    filepath.ToSlash(store.Path()),
	}
	if dockerErr != nil {
		detail["docker_warning"] = dockerErr.Error()
	}
	if revokeErr != nil {
		detail["revoke_warning"] = revokeErr.Error()
	}
	if err := writeAudit(*auditFile, "aborted", detail); err != nil {
		return err
	}

	// (e) Ringkasan.
	fmt.Printf("abort: case %q dihentikan\n", *caseID)
	if dockerErr != nil {
		fmt.Printf("  [peringatan] kill container gagal: %v\n", dockerErr)
		fmt.Println("  periksa sisa container: docker ps -a --filter label=hermes.case=" + *caseID)
	} else {
		fmt.Printf("  container di-kill (label %s=%s): %d\n", dockerx.LabelCase, *caseID, killed)
	}
	fmt.Printf("  state file : %s (task baru untuk case ini ditolak)\n", filepath.ToSlash(marker))
	fmt.Printf("  approval   : %d dicabut (revoked-by-abort, store %s)\n", revokedN, filepath.ToSlash(store.Path()))
	fmt.Println("  audit      : entry 'aborted' ditulis (hash chain)")
	if revokeErr != nil {
		fmt.Printf("  [peringatan] revoke approval gagal: %v\n", revokeErr)
	}
	// Marker dan audit adalah jaminan utama kill switch. Kegagalan Docker atau
	// revoke sudah dilaporkan sebagai warning; caller tetap mendapat sukses
	// setelah state ABORTED durable sehingga task baru ditolak fail-closed.
	return nil
}
