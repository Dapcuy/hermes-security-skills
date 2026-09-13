// Command wrapper adalah fail-closed policy gate di depan httpx
// (ROADMAP §13.1: tool pihak ketiga tidak pernah jalan "telanjang").
//
// Tanggung jawab wrapper (urutan eksekusi):
//
//	1. Verifikasi policy bundle — SHA-256 file bundle harus sama dengan
//	   env POLICY_BUNDLE_SHA256. Fail-closed: env hilang, file hilang,
//	   atau hash mismatch = REJECT, httpx tidak pernah dieksekusi.
//	2. Scope check SETIAP URL target — target boleh datang dari argumen
//	   posisional wrapper (satu atau lebih URL) dan/atau file daftar URL
//	   (--list). SEMUA host wajib cocok bundle.allowed_hosts; satu saja
//	   yang di luar scope = REJECT seluruh run (fail-closed, §8).
//	3. Terapkan budget dari bundle — rate_limit_rps diteruskan ke
//	   httpx sebagai -rate-limit; max_requests/rate_limit_rps (+grace)
//	   menjadi DEADLINE eksekusi; lewat deadline, httpx di-kill
//	   (stop condition "request budget habis", §10).
//	4. Eksekusi httpx sebagai subprocess dengan argumen TERBATAS —
//	   -u <url> (satu target) atau -l <file> (banyak target), -o,
//	   -status-code, -title, -tech-detect, -json, -duc (disable update
//	   check). Tidak ada pass-through argumen mentah; tidak ada shell
//	   (os/exec langsung → tidak bisa argumen injection).
//	5. Parse output JSONL → tulis validation-result.json dengan status
//	   "observed" + provenance (§13.1: tanpa langkah ini, output tool jadi
//	   finding ilegal yang membypass finding lifecycle §26).
//
// Exit code:
//
//	0 = validation-result.json berhasil ditulis
//	1 = kegagalan eksekusi httpx (tanpa result ditulis)
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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	validatorID      = "tool-httpx"
	validatorVersion = "0.1.0"

	// toolName / toolVersion untuk provenance evidence (§13.1).
	// HARUS sama dengan pin di runtimes/docker/images/tool-httpx/Dockerfile —
	// ganti keduanya bersamaan.
	toolName    = "httpx"
	toolVersion = "v1.12.0"

	// envBundleSHA256 menyimpan hex SHA-256 yang diharapkan untuk file
	// policy bundle (di-set oleh control plane saat menjalankan container).
	envBundleSHA256 = "POLICY_BUNDLE_SHA256"

	// Nama file output mentah httpx (JSONL), diletakkan bersebelahan dengan
	// validation-result.json dan dirujuk sebagai evidence ref.
	rawOutputName = "httpx-output.json"

	// budgetGrace adalah grace period (detik) di luar hitungan
	// max_requests / rate_limit_rps — margin untuk DNS, TLS handshake,
	// dan startup proses, agar budget tidak memotong eksekusi yang sah.
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
	fmt.Fprintf(os.Stderr, "tool-httpx wrapper: fail-closed: %s\n", fmt.Sprintf(format, args...))
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

// hostPort menormalkan URL menjadi "host:port".
//
// Catatan MVP: scope matching di wrapper sengaja sederhana (exact match).
// Matcher lengkap (hostname parsing, DNS, private IP, redirect) adalah
// tanggung jawab control plane + hermes-proxy (§8, §11). Wrapper adalah
// lapisan pertahanan kedua, bukan pengganti.
func hostPort(rawURL string) (string, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("target tidak bisa diparse sebagai URL: %w", err)
	}
	scheme := u.Scheme
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("scheme tidak didukung: %q (hanya http/https)", scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", "", errors.New("target tanpa hostname")
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return host, port, nil
}

// inScope mengecek host:port terhadap allowed_hosts.
// Entry "host:port" cocok exact; entry "host" (tanpa port) hanya cocok
// untuk port default 443/80 — port non-default wajib dinyatakan eksplisit.
func inScope(bundle *policyBundle, rawURL string) error {
	host, port, err := hostPort(rawURL)
	if err != nil {
		return err
	}
	pair := host + ":" + port
	for _, entry := range bundle.AllowedHosts {
		entry = strings.TrimSpace(entry)
		if entry == pair {
			return nil
		}
		if !strings.Contains(entry, ":") && entry == host && (port == "443" || port == "80") {
			return nil
		}
	}
	return fmt.Errorf("URL %s (host %s port %s) di luar allowed_hosts bundle — scope check gagal (§8)", rawURL, host, port)
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

// urlList adalah flag multi-nilai untuk -u (semantik httpx: boleh diulang,
// satu nilai boleh memuat daftar dipisah koma).
type urlList []string

func (m *urlList) String() string { return strings.Join(*m, ",") }
func (m *urlList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*m = append(*m, part)
		}
	}
	return nil
}

// fileList adalah flag multi-nilai untuk -l/--list (file daftar URL,
// satu URL per baris; boleh diulang).
type fileList []string

func (m *fileList) String() string { return strings.Join(*m, ",") }
func (m *fileList) Set(v string) error {
	if v = strings.TrimSpace(v); v != "" {
		*m = append(*m, v)
	}
	return nil
}

// collectTargets mengumpulkan URL target dari flag -u, file -l/--list
// (satu URL per baris), dan argumen posisional, lalu scope check SEMUANYA.
// Satu target saja di luar scope = error (fail-closed untuk seluruh run).
func collectTargets(bundle *policyBundle, urls urlList, lists fileList, positional []string) ([]string, error) {
	var targets []string
	targets = append(targets, urls...)
	for _, listPath := range lists {
		data, err := os.ReadFile(listPath)
		if err != nil {
			return nil, fmt.Errorf("file -l tidak bisa dibaca (%s): %w", listPath, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, line)
		}
	}
	targets = append(targets, positional...)
	if len(targets) == 0 {
		return nil, errors.New("tidak ada target — berikan -u <url>, -l <file>, atau URL posisional")
	}
	for _, t := range targets {
		if err := inScope(bundle, t); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

// probeEvent adalah subset field JSONL output httpx yang dipakai wrapper
// untuk normalisasi (runner/types.go httpx v1.12.0).
type probeEvent struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
}

// parseProbes membaca output JSONL httpx dan menormalkannya menjadi
// observations dengan detail "<url> [<status>] [<title>] [<tech>]".
func parseProbes(path string) ([]observation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var obs []observation
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev probeEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return obs, fmt.Errorf("baris output httpx bukan JSON valid (baris %d): %w", i+1, err)
		}
		if ev.URL == "" {
			continue
		}
		detail := ev.URL
		detail += fmt.Sprintf(" [%d]", ev.StatusCode)
		if ev.Title != "" {
			detail += " [" + ev.Title + "]"
		}
		if len(ev.Tech) > 0 {
			detail += " [" + strings.Join(ev.Tech, ",") + "]"
		}
		obs = append(obs, observation{Type: "probe", Detail: detail})
	}
	return obs, nil
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
	httpxBin := flag.String("httpx", "/usr/bin/httpx", "path binary httpx")
	// Flag target dipahami wrapper langsung dengan semantik httpx (-u
	// boleh diulang/dipisah koma, -l/--list file daftar URL). Flag httpx
	// LAIN (-o, -status-code, -title, -tech-detect, -json, -duc,
	// -rate-limit) selalu di-set wrapper sendiri — whitelist tertutup,
	// caller tidak bisa menambah/override.
	var urls urlList
	var lists fileList
	flag.Var(&urls, "u", "URL target (semantik -u httpx; boleh diulang atau dipisah koma)")
	flag.Var(&lists, "l", "file daftar URL, satu per baris (semantik -l httpx; boleh diulang)")
	flag.Var(&lists, "list", "alias -l")
	flag.Parse()

	// 1. Fail-closed: tanpa env hash, bundle tidak dianggap terverifikasi.
	expectedHex := os.Getenv(envBundleSHA256)
	bundle, err := verifyBundle(*bundlePath, expectedHex)
	if err != nil {
		return failClosed("%v", err)
	}

	// 2. Kumpulkan + scope check SETIAP URL target (control plane tetap
	// gate pertama, §8). Satu saja di luar scope = REJECT seluruh run.
	targets, err := collectTargets(bundle, urls, lists, flag.Args())
	if err != nil {
		return failClosed("%v", err)
	}

	// Task ID untuk provenance result.
	taskID, err := loadTaskID(*taskPath)
	if err != nil {
		return failClosed("%v", err)
	}

	// 3. Budget dari bundle: -rate-limit diteruskan ke httpx; deadline =
	// max_requests/rate_limit_rps (+grace). Lewat deadline, httpx di-kill
	// (stop condition §10).
	budgetSeconds := bundle.MaxRequests/bundle.RateLimitRPS + budgetGraceSeconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(budgetSeconds)*time.Second)
	defer cancel()

	// 4. Eksekusi httpx dengan argumen TERBATAS (whitelist, bukan
	// passthrough). Satu target → -u; banyak target → ditulis ke file
	// sementara dan diteruskan via -l.
	rawOutPath := filepath.Join(filepath.Dir(*outPath), rawOutputName)
	cmdArgs := []string{
		"-o", rawOutPath,
		"-status-code",
		"-title",
		"-tech-detect",
		"-json",
		"-duc", // disable update check — runtime tidak pernah meng-update (§13.1)
		"-rate-limit", fmt.Sprintf("%d", bundle.RateLimitRPS),
	}
	if len(targets) == 1 {
		cmdArgs = append(cmdArgs, "-u", targets[0])
	} else {
		tmp, err := os.CreateTemp("", "httpx-targets-*.txt")
		if err != nil {
			return failClosed("gagal membuat file daftar target sementara: %v", err)
		}
		listFile := tmp.Name()
		defer os.Remove(listFile)
		for _, t := range targets {
			if _, wErr := fmt.Fprintln(tmp, t); wErr != nil {
				tmp.Close()
				return failClosed("gagal menulis file daftar target: %v", wErr)
			}
		}
		if err := tmp.Close(); err != nil {
			return failClosed("gagal menutup file daftar target: %v", err)
		}
		cmdArgs = append(cmdArgs, "-l", listFile)
	}
	cmd := exec.CommandContext(ctx, *httpxBin, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmdErr := cmd.Run()

	budgetExceeded := errors.Is(cmdErr, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmdErr != nil && !budgetExceeded {
		// httpx gagal (binary rusak, dsb.) — jangan tulis result yang
		// menyesatkan; laporkan via exit code.
		return failClosed("httpx gagal dieksekusi: %v", cmdErr)
	}
	if budgetExceeded {
		fmt.Fprintf(os.Stderr, "tool-httpx wrapper: budget stop — deadline %ds tercapai, httpx di-kill (§10 request budget habis)\n", budgetSeconds)
	}

	// 5. Parse output JSONL → validation-result.json.
	evidenceRefs := []string{}
	observations := []observation{}
	if _, statErr := os.Stat(rawOutPath); statErr == nil {
		obs, parseErr := parseProbes(rawOutPath)
		if parseErr != nil {
			// Output ada tapi korup: tetap dirujuk agar adapter bisa
			// menandai evidence rusak.
			fmt.Fprintf(os.Stderr, "tool-httpx wrapper: peringatan parse output: %v\n", parseErr)
		}
		observations = append(observations, obs...)
		evidenceRefs = append(evidenceRefs, rawOutPath)
	} else if budgetExceeded {
		fmt.Fprintln(os.Stderr, "tool-httpx wrapper: tidak ada output httpx (budget tercapai sebelum hasil pertama)")
	}
	fmt.Fprintf(os.Stderr, "tool-httpx wrapper: %d URL terprobe\n", len(observations))

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
	fmt.Fprintf(os.Stderr, "tool-httpx wrapper: result ditulis ke %s\n", *outPath)
	return 0
}

func main() {
	os.Exit(run())
}
