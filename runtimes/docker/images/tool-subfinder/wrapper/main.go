// Command wrapper adalah fail-closed policy gate di depan subfinder
// (ROADMAP §13.1: tool pihak ketiga tidak pernah jalan "telanjang").
//
// Tanggung jawab wrapper (urutan eksekusi):
//
//	1. Verifikasi policy bundle — SHA-256 file bundle harus sama dengan
//	   env POLICY_BUNDLE_SHA256. Fail-closed: env hilang, file hilang,
//	   atau hash mismatch = REJECT, subfinder tidak pernah dieksekusi.
//	2. Scope check domain — domain pada -d WAJIB cocok exact dengan host
//	   pada bundle.allowed_hosts. Ini memastikan hanya domain in-scope yang
//	   di-enumerate (§8). Tidak ada wildcard, tidak ada prefix/suffix match.
//	3. Terapkan budget sederhana dari bundle — subfinder adalah passive
//	   recon (tidak ada flag rate limit per-request), jadi max_requests /
//	   rate_limit_rps di-map ke DEADLINE eksekusi (max_requests/rate_limit_rps
//	   + grace); lewat deadline, subfinder di-kill (stop condition §10).
//	4. Eksekusi subfinder sebagai subprocess dengan argumen TERBATAS —
//	   -d <domain>, -o <file>, -silent, -duc (disable update check —
//	   runtime tidak pernah mengunduh/meng-update apa pun, §13.1).
//	   Tidak ada pass-through argumen mentah; tidak ada shell (os/exec
//	   langsung → tidak bisa argumen injection). -json TIDAK dipakai:
//	   output subfinder cukup berupa text per baris subdomain.
//	5. Parse output text per baris → tulis validation-result.json dengan
//	   status "observed" + provenance (§13.1: tanpa langkah ini, output
//	   tool jadi finding ilegal yang membypass finding lifecycle §26).
//
// CATATAN DESAIN (passive recon): subfinder mengakses THIRD-PARTY DATA
// SOURCES PUBLIK (crt.sh, hackertone, dnsdumpster, dsb.) — BUKAN target
// in-scope. Itulah sifat passive subdomain enumeration. Scope check tetap
// wajib untuk memastikan DOMAIN YANG DI-ENUMERATE adalah domain in-scope;
// koneksi keluar ke data sources adalah perilaku normal passive recon dan
// tidak memerlukan approval "active scanning" (§8). Versi tool dicatat di
// provenance; hasil enumerasi tetap observation — Hermes yang menafsirkan
// (§17).
//
// Exit code:
//
//	0 = validation-result.json berhasil ditulis
//	1 = kegagalan eksekusi subfinder (tanpa result ditulis)
//	2 = fail-closed policy (bundle/env/scope/task tidak valid)
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	validatorID      = "tool-subfinder"
	validatorVersion = "0.1.0"

	// toolName / toolVersion untuk provenance evidence (§13.1).
	// HARUS sama dengan pin di runtimes/docker/images/tool-subfinder/Dockerfile —
	// ganti keduanya bersamaan.
	toolName    = "subfinder"
	toolVersion = "v2.16.0"

	// envBundleSHA256 menyimpan hex SHA-256 yang diharapkan untuk file
	// policy bundle (di-set oleh control plane saat menjalankan container).
	envBundleSHA256 = "POLICY_BUNDLE_SHA256"

	// Nama file output mentah subfinder (text per baris), diletakkan
	// bersebelahan dengan validation-result.json dan dirujuk sebagai
	// evidence ref.
	rawOutputName = "subfinder-output.txt"

	// budgetGrace adalah grace period (detik) di luar hitungan
	// max_requests / rate_limit_rps — margin untuk DNS, handshake, dan
	// startup proses, agar budget tidak memotong eksekusi yang sah.
	budgetGraceSeconds = 30
)

// policyBundle adalah bentuk policy bundle proxy (§11, §38):
// schema resmi ada di runtimes/proxy/policy-bundle/schema.json.
type policyBundle struct {
	Version      int      `json:"version"`
	AllowedHosts []string `json:"allowed_hosts"`
	MaxRequests  int      `json:"max_requests"`
	RateLimitRPS int      `json:"rate_limit_rps"`
}

// observation adalah satu temuan mentah hasil normalisasi output tool.
type observation struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// validationResult adalah kontrak Docker Execution Contract (§17).
// Status selalu "observed": tool tidak boleh menetapkan status
// vulnerability final (§17 — Hermes yang menafsirkan).
type validationResult struct {
	TaskID       string            `json:"task_id"`
	Validator    validatorIdentity `json:"validator"`
	Status       string            `json:"status"`
	Observations []observation     `json:"observations"`
	EvidenceRefs []string          `json:"evidence_refs"`
	Provenance   provenance        `json:"provenance"`
}

type validatorIdentity struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type provenance struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
}

func failClosed(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "tool-subfinder wrapper: fail-closed: %s\n", fmt.Sprintf(format, args...))
	return 2
}

// verifyBundle memverifikasi file bundle terhadap hex SHA-256 yang
// diharapkan (constant-time compare), lalu mem-parsing isinya.
func verifyBundle(path, expectedHex string) (*policyBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy bundle tidak bisa dibaca: %w", err)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])

	expected := strings.ToLower(strings.TrimSpace(expectedHex))
	if expected == "" {
		return nil, errors.New("env POLICY_BUNDLE_SHA256 kosong — bundle tidak diverifikasi = tolak")
	}
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return nil, fmt.Errorf("SHA-256 bundle mismatch: actual=%s expected=%s (bundle mungkin tampered)", actual, expected)
	}

	var bundle policyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("policy bundle bukan JSON valid: %w", err)
	}
	// Validasi ketat — bundle yang setengah jalan = fail-closed.
	if bundle.Version < 1 {
		return nil, fmt.Errorf("bundle.version tidak valid: %d", bundle.Version)
	}
	if len(bundle.AllowedHosts) == 0 {
		return nil, errors.New("bundle.allowed_hosts kosong — tidak ada scope berarti tolak semua")
	}
	if bundle.MaxRequests <= 0 {
		return nil, fmt.Errorf("bundle.max_requests harus > 0, dapat: %d", bundle.MaxRequests)
	}
	if bundle.RateLimitRPS <= 0 {
		return nil, fmt.Errorf("bundle.rate_limit_rps harus > 0, dapat: %d", bundle.RateLimitRPS)
	}
	return &bundle, nil
}

// normalizeDomain menormalkan domain target: lowercase, tanpa trailing dot.
// Strict: domain wajib memuat titik (FQDN), tanpa scheme/port/wildcard —
// sesuatu yang lain berarti upaya meloloskan target di luar scope.
func normalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", errors.New("domain kosong")
	}
	if strings.ContainsAny(d, "/:*@ \t") || strings.Contains(d, ":") {
		return "", fmt.Errorf("domain mengandung karakter tidak sah: %q (hanya FQDN tanpa scheme/port/wildcard)", raw)
	}
	if !strings.Contains(d, ".") {
		return "", fmt.Errorf("domain bukan FQDN (tanpa titik): %q", raw)
	}
	return d, nil
}

// domainInScope mengecek domain target terhadap allowed_hosts.
// Entry boleh berbentuk "host" atau "host:port" — yang dibandingkan adalah
// BAGIAN HOST-nya, exact match (case-insensitive). Entry wildcard ("*")
// diabaikan (fail-closed: wildcard tidak pernah cocok).
//
// Catatan MVP: scope matching di wrapper sengaja sederhana (exact match).
// Matcher lengkap (DNS, wildcard scope program bug bounty, dsb.) adalah
// tanggung jawab control plane (§8). Wrapper adalah lapisan pertahanan
// kedua, bukan pengganti.
func domainInScope(bundle *policyBundle, domain string) error {
	for _, entry := range bundle.AllowedHosts {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if strings.Contains(entry, "*") {
			continue
		}
		host := entry
		if h, _, ok := strings.Cut(entry, ":"); ok && h != "" {
			host = h
		}
		if host == domain {
			return nil
		}
	}
	return fmt.Errorf("domain %s di luar allowed_hosts bundle — hanya domain in-scope yang boleh di-enumerate (§8)", domain)
}

// loadTaskID membaca validation-task.json dan mengambil task_id (§17).
func loadTaskID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("validation-task.json tidak bisa dibaca: %w", err)
	}
	var task struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(data, &task); err != nil {
		return "", fmt.Errorf("validation-task.json bukan JSON valid: %w", err)
	}
	if strings.TrimSpace(task.TaskID) == "" {
		return "", errors.New("task_id kosong pada validation-task.json")
	}
	return task.TaskID, nil
}

// hostnameRe untuk sanity check tiap baris output subfinder: subdomain
// hanya boleh berisi karakter hostname. Baris aneh (warning tool yang
// bocor ke file output, dsb.) di-skip dengan peringatan, bukan dipercaya.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// parseSubdomains membaca output text subfinder (satu subdomain per baris)
// dan menormalkannya menjadi observations.
func parseSubdomains(path string) ([]observation, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var obs []observation
	skipped := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !hostnameRe.MatchString(line) || !strings.Contains(line, ".") {
			skipped++
			fmt.Fprintf(os.Stderr, "tool-subfinder wrapper: peringatan: baris output tidak seperti hostname, di-skip: %q\n", line)
			continue
		}
		obs = append(obs, observation{Type: "subdomain", Detail: strings.ToLower(line)})
	}
	return obs, skipped, nil
}

func writeResult(path string, res validationResult) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("direktori output tidak bisa dibuat: %w", err)
		}
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func run() int {
	bundlePath := flag.String("bundle", "", "path policy bundle (wajib, hash-verified via POLICY_BUNDLE_SHA256)")
	taskPath := flag.String("input", "/workspace/input/validation-task.json", "path validation-task.json")
	outPath := flag.String("output", "/workspace/output/validation-result.json", "path validation-result.json")
	subfinderBin := flag.String("subfinder", "/usr/bin/subfinder", "path binary subfinder")
	// -d dipahami wrapper langsung (semantik sama dengan -d subfinder);
	// nilai -d/-o/-silent/-duc ke subfinder selalu di-set wrapper (whitelist
	// tertutup), caller tidak bisa menambah/override flag subfinder lain.
	domainFlag := flag.String("d", "", "domain target (semantik -d subfinder); alternatif argumen posisional")
	flag.Parse()

	// Target WAJIB satu: -d <domain> ATAU satu argumen posisional — bukan
	// keduanya. Tidak ada pass-through flag subfinder apa pun.
	args := flag.Args()
	if len(args) > 1 {
		return failClosed("argumen posisional ekstra tidak di-whitelist: %q", args[1:])
	}
	raw := ""
	if len(args) == 1 {
		raw = args[0]
	}
	if strings.TrimSpace(*domainFlag) != "" {
		if raw != "" && raw != *domainFlag {
			return failClosed("target ganda dan berbeda: posisional %q vs -d %q", raw, *domainFlag)
		}
		raw = *domainFlag
	}
	if raw == "" {
		return failClosed("domain target wajib: -d <domain> atau satu argumen posisional")
	}
	domain, err := normalizeDomain(raw)
	if err != nil {
		return failClosed("%v", err)
	}

	// 1. Fail-closed: tanpa env hash, bundle tidak dianggap terverifikasi.
	expectedHex := os.Getenv(envBundleSHA256)
	bundle, err := verifyBundle(*bundlePath, expectedHex)
	if err != nil {
		return failClosed("%v", err)
	}

	// 1b. Scope check domain (control plane tetap gate pertama, §8):
	// hanya domain in-scope yang di-enumerate. Koneksi subfinder ke
	// third-party data sources publik (crt.sh, dsb.) BUKAN akses ke target
	// — itu sifat passive recon (lihat CATATAN DESAIN di header).
	if err := domainInScope(bundle, domain); err != nil {
		return failClosed("%v", err)
	}

	// Task ID untuk provenance result.
	taskID, err := loadTaskID(*taskPath)
	if err != nil {
		return failClosed("%v", err)
	}

	// 2. Budget sederhana dari bundle: subfinder passive (tidak ada flag
	// rate-limit per-request), jadi budget di-map ke deadline eksekusi
	// (max_requests/rate_limit_rps + grace). Lewat deadline, subfinder
	// di-kill (stop condition §10).
	budgetSeconds := bundle.MaxRequests/bundle.RateLimitRPS + budgetGraceSeconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(budgetSeconds)*time.Second)
	defer cancel()

	// 3. Eksekusi subfinder dengan argumen TERBATAS (whitelist, bukan
	// passthrough). -silent = hanya hasil; -duc = disable update check
	// (runtime tidak pernah meng-update tool/sources, §13.1). -json tidak
	// dipakai — output text per baris cukup dan lebih mudah dinormalisasi.
	rawOutPath := filepath.Join(filepath.Dir(*outPath), rawOutputName)
	cmdArgs := []string{
		"-d", domain,
		"-o", rawOutPath,
		"-silent",
		"-duc",
	}
	cmd := exec.CommandContext(ctx, *subfinderBin, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmdErr := cmd.Run()

	budgetExceeded := errors.Is(cmdErr, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmdErr != nil && !budgetExceeded {
		// Subfinder gagal (binary rusak, jaringan bermasalah, dsb.) —
		// jangan tulis result yang menyesatkan; laporkan via exit code.
		return failClosed("subfinder gagal dieksekusi: %v", cmdErr)
	}
	if budgetExceeded {
		fmt.Fprintf(os.Stderr, "tool-subfinder wrapper: budget stop — deadline %ds tercapai, subfinder di-kill (§10 request budget habis)\n", budgetSeconds)
	}

	// 4. Parse output text per baris → validation-result.json.
	evidenceRefs := []string{}
	observations := []observation{}
	if _, statErr := os.Stat(rawOutPath); statErr == nil {
		obs, skipped, parseErr := parseSubdomains(rawOutPath)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "tool-subfinder wrapper: peringatan parse output: %v\n", parseErr)
		} else if skipped > 0 {
			fmt.Fprintf(os.Stderr, "tool-subfinder wrapper: %d baris output di-skip (bukan hostname)\n", skipped)
		}
		observations = append(observations, obs...)
		evidenceRefs = append(evidenceRefs, rawOutPath)
	} else if budgetExceeded {
		fmt.Fprintln(os.Stderr, "tool-subfinder wrapper: tidak ada output subfinder (budget tercapai sebelum hasil pertama)")
	}
	fmt.Fprintf(os.Stderr, "tool-subfinder wrapper: %d subdomain terobservasi\n", len(observations))

	res := validationResult{
		TaskID:       taskID,
		Validator:    validatorIdentity{ID: validatorID, Version: validatorVersion},
		Status:       "observed", // tool tidak pernah menyatakan status final (§17)
		Observations: observations,
		EvidenceRefs: evidenceRefs,
		Provenance: provenance{
			Tool:        toolName,
			ToolVersion: toolVersion,
		},
	}
	if err := writeResult(*outPath, res); err != nil {
		return failClosed("gagal menulis validation-result.json: %v", err)
	}
	fmt.Fprintf(os.Stderr, "tool-subfinder wrapper: result ditulis ke %s\n", *outPath)
	return 0
}

func main() {
	os.Exit(run())
}
