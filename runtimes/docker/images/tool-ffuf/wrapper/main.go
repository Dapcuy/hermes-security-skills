// Command wrapper adalah fail-closed policy gate di depan ffuf
// (ROADMAP §13.1: tool pihak ketiga tidak pernah jalan "telanjang").
//
// Tanggung jawab wrapper (urutan eksekusi):
//
//	1. Verifikasi policy bundle — SHA-256 file bundle harus sama dengan
//	   env POLICY_BUNDLE_SHA256. Fail-closed: env hilang, file hilang,
//	   atau hash mismatch = REJECT, ffuf tidak pernah dieksekusi.
//	2. Scope check target URL — URL WAJIB cocok bundle.allowed_hosts
//	   (entry "host:port" exact; entry "host" hanya untuk port default
//	   80/443). Fail-closed (§8).
//	3. Wordlist ter-bake WAJIB (pola --templates tool-nuclei) — wrapper
//	   MENOLAK jalan (exit 2) bila --wordlist tidak diberikan, file tidak
//	   ada, atau kosong. Wordlist di-BAKE ke image saat build pada tag
//	   SecLists terpin (ARG SECLISTS_TAG) dan TIDAK PERNAH di-download
//	   saat runtime; wrapper membaca /wordlists/.hermes-wordlists-version
//	   untuk provenance versi wordlist.
//	4. Terapkan budget dari bundle — rate_limit_rps diteruskan ke ffuf
//	   sebagai -rate; max_requests/rate_limit_rps (+grace) menjadi
//	   DEADLINE eksekusi; lewat deadline, ffuf di-kill (stop condition
//	   §10). Threads (-t) dibatasi maksimal 10 (fail-closed jika lebih).
//	5. Eksekusi ffuf sebagai subprocess dengan argumen TERBATAS — -w,
//	   -u, -o, -of json, -mc, -fc (opsional), -t, -rate. Tidak ada
//	   pass-through argumen mentah; tidak ada shell (os/exec langsung →
//	   tidak bisa argumen injection).
//	6. Parse output JSON ffuf → tulis validation-result.json dengan
//	   status "observed" + provenance (§13.1: tanpa langkah ini, output
//	   tool jadi finding ilegal yang membypass finding lifecycle §26).
//
// Exit code:
//
//	0 = validation-result.json berhasil ditulis
//	1 = kegagalan eksekusi ffuf (tanpa result ditulis)
//	2 = fail-closed policy (bundle/env/scope/wordlist/task tidak valid)
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
	"regexp"
	"strings"
	"time"
)

const (
	validatorID      = "tool-ffuf"
	validatorVersion = "0.1.0"

	// toolName / toolVersion untuk provenance evidence (§13.1).
	// HARUS sama dengan pin di runtimes/docker/images/tool-ffuf/Dockerfile —
	// ganti keduanya bersamaan.
	toolName    = "ffuf"
	toolVersion = "v2.3.0"

	// envBundleSHA256 menyimpan hex SHA-256 yang diharapkan untuk file
	// policy bundle (di-set oleh control plane saat menjalankan container).
	envBundleSHA256 = "POLICY_BUNDLE_SHA256"

	// defaultWordlistsDir adalah lokasi wordlist ter-bake di image (§13.1).
	defaultWordlistsDir = "/wordlists"

	// wordlistsVersionFile berisi tag SecLists terpin yang ditulis
	// Dockerfile saat bake; dibaca wrapper untuk provenance.
	wordlistsVersionFile = ".hermes-wordlists-version"

	// Nama file output mentah ffuf (JSON), diletakkan bersebelahan dengan
	// validation-result.json dan dirujuk sebagai evidence ref.
	rawOutputName = "ffuf-output.json"

	// budgetGrace adalah grace period (detik) di luar hitungan
	// max_requests / rate_limit_rps — margin untuk DNS, TLS handshake,
	// dan startup proses, agar budget tidak memotong eksekusi yang sah.
	budgetGraceSeconds = 30

	// maxThreads membatasi agresivitas fuzzing (§13.1: tool mass-scanner
	// agresif secara default) — -t melebihi ini = fail-closed.
	maxThreads = 10

	// defaultMC adalah nilai -mc (match status codes) default wrapper.
	// ffuf default-nya memfilter sebagian besar kode; eksplisit di sini
	// agar hasil deterministik antar versi ffuf.
	defaultMC = "200,204,301,302,307,308,401,403"
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
// Status selalu "observed": tool scanner tidak boleh menetapkan status
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
	Tool             string `json:"tool"`
	ToolVersion      string `json:"tool_version"`
	WordlistsVersion string `json:"wordlists_version,omitempty"`
}

func failClosed(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "tool-ffuf wrapper: fail-closed: %s\n", fmt.Sprintf(format, args...))
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

// verifyWordlist memastikan wordlist ter-bake benar-benar tersedia sebelum
// ffuf dieksekusi (§13.1). Fail-closed: --wordlist kosong, path tidak ada,
// bukan file biasa, atau berukuran 0 = REJECT (exit 2) — fuzzing tanpa
// wordlist ter-bake dilarang karena itu tanda aset akan di-download saat
// runtime. Mengembalikan versi wordlist terpin untuk provenance (cari
// wordlistsVersionFile di direktori wordlist dan maksimal 6 level di
// atasnya; "unknown" bila tidak ketemu).
func verifyWordlist(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--wordlist wajib diisi (fuzzing tanpa wordlist ter-bake dilarang, §13.1)")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("wordlist ter-bake tidak ada di %s — mount salah / bukan aset bake, tolak jalan (§13.1): %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("--wordlist harus file, dapat: %s (dir/pipe tidak diterima)", path)
	}
	if info.Size() == 0 {
		return "", fmt.Errorf("wordlist kosong (0 byte): %s — tolak jalan (§13.1)", path)
	}
	version := ""
	lookup := filepath.Dir(path)
	for i := 0; i < 6 && version == ""; i++ {
		if data, readErr := os.ReadFile(filepath.Join(lookup, wordlistsVersionFile)); readErr == nil {
			version = strings.TrimSpace(string(data))
		} else {
			parent := filepath.Dir(lookup)
			if parent == lookup {
				break
			}
			lookup = parent
		}
	}
	if version == "" {
		fmt.Fprintf(os.Stderr, "tool-ffuf wrapper: peringatan: file versi wordlist tidak terbaca, provenance wordlists_version=unknown\n")
		version = "unknown"
	}
	return version, nil
}

// validateCodes memvalidasi nilai -mc/-fc: hanya digit, koma, dash
// (ffuf menerima "200,204" dan range "200-299") atau "all". Fail-closed
// terhadap karakter lain agar tidak ada nilai aneh yang diteruskan.
func validateCodes(v string) (string, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return "", errors.New("nilai status code kosong")
	}
	if s == "all" {
		return s, nil
	}
	if !codeSpecRe.MatchString(s) {
		return "", fmt.Errorf("format status code tidak valid: %q (gunakan digit, koma, dash, atau \"all\")", v)
	}
	return s, nil
}

var codeSpecRe = regexp.MustCompile(`^[0-9]{1,3}(-[0-9]{1,3})?(,[0-9]{1,3}(-[0-9]{1,3})?)*$`)

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

// ffufResult adalah subset field JSON output ffuf yang dipakai wrapper
// untuk normalisasi.
type ffufResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int64  `json:"length"`
}

type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

// parseFfufOutput membaca output JSON ffuf (-of json) dan menormalkannya
// menjadi observations dengan detail "<url> [status] [size]".
func parseFfufOutput(path string) ([]observation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out ffufOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("output ffuf bukan JSON valid: %w", err)
	}
	obs := make([]observation, 0, len(out.Results))
	for _, r := range out.Results {
		if r.URL == "" {
			continue
		}
		obs = append(obs, observation{
			Type:   "fuzz_hit",
			Detail: fmt.Sprintf("%s [%d] [%d]", r.URL, r.Status, r.Length),
		})
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

// wordlistList adalah flag multi-nilai untuk -w (semantik ffuf: boleh
// diulang; satu nilai boleh memuat daftar dipisah koma dan/atau akhiran
// ":KEYWORD"). Setiap path file tetap diverifikasi satu per satu.
type wordlistList []string

func (m *wordlistList) String() string { return strings.Join(*m, ",") }
func (m *wordlistList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*m = append(*m, part)
		}
	}
	return nil
}

// wordlistPaths mengekstrak path file dari entri -w (buang akhiran
// ":KEYWORD" bila ada) untuk verifikasi fail-closed.
func wordlistPaths(entries wordlistList) ([]string, error) {
	var paths []string
	for _, e := range entries {
		for _, part := range strings.Split(e, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if path, _, ok := strings.Cut(part, ":"); ok && path != "" {
				part = path
			}
			paths = append(paths, part)
		}
	}
	if len(paths) == 0 {
		return nil, errors.New("--wordlist/-w wajib diisi (fuzzing tanpa wordlist ter-bake dilarang, §13.1)")
	}
	return paths, nil
}

func run() int {
	bundlePath := flag.String("bundle", "", "path policy bundle (wajib, hash-verified via POLICY_BUNDLE_SHA256)")
	taskPath := flag.String("input", "/workspace/input/validation-task.json", "path validation-task.json")
	outPath := flag.String("output", "/workspace/output/validation-result.json", "path validation-result.json")
	ffufBin := flag.String("ffuf", "/usr/bin/ffuf", "path binary ffuf")
	// Flag dipahami wrapper langsung dengan semantik ffuf. Flag ffuf LAIN
	// (-o, -of, -rate) selalu di-set wrapper sendiri — whitelist tertutup,
	// caller tidak bisa menambah/override flag ffuf lain.
	var wordlists wordlistList
	targetFlag := flag.String("u", "", "URL target dengan kata kunci FUZZ (semantik -u ffuf); alternatif argumen posisional")
	flag.Var(&wordlists, "w", "wordlist ter-bake (semantik -w ffuf; WAJIB, boleh diulang/dipisah koma, dukung :KEYWORD)")
	flag.Var(&wordlists, "wordlist", "alias -w")
	mc := flag.String("mc", defaultMC, "match status codes (-mc ffuf), format digit/koma/dash atau all")
	fc := flag.String("fc", "", "filter status codes (-fc ffuf), opsional")
	threads := flag.Int("t", maxThreads, "jumlah thread concurrent, maksimal 10 (fail-closed jika lebih)")
	flag.Parse()

	// Target: -u ATAU satu argumen posisional (URL dengan kata kunci FUZZ)
	// — bukan keduanya kecuali nilainya sama.
	args := flag.Args()
	if len(args) > 1 {
		return failClosed("argumen posisional ekstra tidak di-whitelist: %q", args[1:])
	}
	target := *targetFlag
	if len(args) == 1 {
		if target != "" && target != args[0] {
			return failClosed("target ganda dan berbeda: posisional %q vs -u %q", args[0], target)
		}
		target = args[0]
	}
	if strings.TrimSpace(target) == "" {
		return failClosed("target URL wajib: -u <url> atau satu argumen posisional")
	}

	// 1. Fail-closed: tanpa env hash, bundle tidak dianggap terverifikasi.
	expectedHex := os.Getenv(envBundleSHA256)
	bundle, err := verifyBundle(*bundlePath, expectedHex)
	if err != nil {
		return failClosed("%v", err)
	}

	// 2. Scope check target URL (control plane tetap gate pertama, §8).
	if err := inScope(bundle, target); err != nil {
		return failClosed("%v", err)
	}

	// 3. Wordlist ter-bake wajib ada & tidak kosong — fail-closed sebelum
	// ffuf dieksekusi (§13.1, pola --templates tool-nuclei). SEMUA path
	// wordlist (multi -w) diverifikasi satu per satu.
	_, wlStatErr := os.Stat(defaultWordlistsDir)
	if wlStatErr == nil {
		if info, statErr := os.Stat(defaultWordlistsDir); statErr == nil && info.IsDir() {
			if entries, dirErr := os.ReadDir(defaultWordlistsDir); dirErr == nil && len(entries) == 0 {
				return failClosed("direktori wordlist ter-bake kosong: %s — fuzzing tanpa wordlist ter-bake dilarang (§13.1)", defaultWordlistsDir)
			}
		}
	}
	wlPaths, err := wordlistPaths(wordlists)
	if err != nil {
		return failClosed("%v", err)
	}
	wlVersion := ""
	for _, p := range wlPaths {
		v, vErr := verifyWordlist(p)
		if vErr != nil {
			return failClosed("%v", vErr)
		}
		if wlVersion == "" {
			wlVersion = v
		}
	}
	fmt.Fprintf(os.Stderr, "tool-ffuf wrapper: %d wordlist ter-bake terverifikasi (versi SecLists %s)\n", len(wlPaths), wlVersion)

	// 3b. Validasi -mc/-fc dan batas thread.
	mcVal, err := validateCodes(*mc)
	if err != nil {
		return failClosed("-mc: %v", err)
	}
	var fcVal string
	if strings.TrimSpace(*fc) != "" {
		if fcVal, err = validateCodes(*fc); err != nil {
			return failClosed("-fc: %v", err)
		}
	}
	if *threads < 1 || *threads > maxThreads {
		return failClosed("-t harus 1..%d, dapat: %d (fuzzing agresif dilarang, §13.1)", maxThreads, *threads)
	}

	// Task ID untuk provenance result.
	taskID, err := loadTaskID(*taskPath)
	if err != nil {
		return failClosed("%v", err)
	}

	// 4. Budget dari bundle: -rate dari rate_limit_rps; deadline =
	// max_requests/rate_limit_rps (+grace). Lewat deadline, ffuf di-kill
	// (stop condition §10). Catatan: output file ffuf ditulis di akhir
	// run — kill karena budget bisa berarti tidak ada evidence mentah
	// (sama dengan pola tool-nuclei).
	budgetSeconds := bundle.MaxRequests/bundle.RateLimitRPS + budgetGraceSeconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(budgetSeconds)*time.Second)
	defer cancel()

	// 5. Eksekusi ffuf dengan argumen TERBATAS (whitelist, bukan
	// passthrough). -of json agar output normalisasi deterministik.
	rawOutPath := filepath.Join(filepath.Dir(*outPath), rawOutputName)
	cmdArgs := []string{
		"-u", target,
		"-o", rawOutPath,
		"-of", "json",
		"-mc", mcVal,
		"-t", fmt.Sprintf("%d", *threads),
		"-rate", fmt.Sprintf("%d", bundle.RateLimitRPS),
	}
	for _, w := range wordlists { // wordlist ter-bake (wajib, sudah diverifikasi)
		cmdArgs = append(cmdArgs, "-w", w)
	}
	if fcVal != "" {
		cmdArgs = append(cmdArgs, "-fc", fcVal)
	}
	cmd := exec.CommandContext(ctx, *ffufBin, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmdErr := cmd.Run()

	budgetExceeded := errors.Is(cmdErr, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmdErr != nil && !budgetExceeded {
		// ffuf gagal (binary rusak, flag tidak valid, dsb.) — jangan tulis
		// result yang menyesatkan; laporkan via exit code.
		return failClosed("ffuf gagal dieksekusi: %v", cmdErr)
	}
	if budgetExceeded {
		fmt.Fprintf(os.Stderr, "tool-ffuf wrapper: budget stop — deadline %ds tercapai, ffuf di-kill (§10 request budget habis)\n", budgetSeconds)
	}

	// 6. Parse output JSON ffuf → validation-result.json.
	evidenceRefs := []string{}
	observations := []observation{}
	if _, statErr := os.Stat(rawOutPath); statErr == nil {
		obs, parseErr := parseFfufOutput(rawOutPath)
		if parseErr != nil {
			// Output ada tapi korup: tetap dirujuk agar adapter bisa
			// menandai evidence rusak.
			fmt.Fprintf(os.Stderr, "tool-ffuf wrapper: peringatan parse output: %v\n", parseErr)
		}
		observations = append(observations, obs...)
		evidenceRefs = append(evidenceRefs, rawOutPath)
	} else if budgetExceeded {
		fmt.Fprintln(os.Stderr, "tool-ffuf wrapper: tidak ada output ffuf (budget tercapai sebelum selesai)")
	}
	fmt.Fprintf(os.Stderr, "tool-ffuf wrapper: %d fuzz hit terobservasi\n", len(observations))

	res := validationResult{
		TaskID:       taskID,
		Validator:    validatorIdentity{ID: validatorID, Version: validatorVersion},
		Status:       "observed", // tool tidak pernah menyatakan status final (§17)
		Observations: observations,
		EvidenceRefs: evidenceRefs,
		Provenance: provenance{
			Tool:             toolName,
			ToolVersion:      toolVersion,
			WordlistsVersion: wlVersion, // versi SecLists ter-bake (§13.1)
		},
	}
	if err := writeResult(*outPath, res); err != nil {
		return failClosed("gagal menulis validation-result.json: %v", err)
	}
	fmt.Fprintf(os.Stderr, "tool-ffuf wrapper: result ditulis ke %s\n", *outPath)
	return 0
}

func main() {
	os.Exit(run())
}
