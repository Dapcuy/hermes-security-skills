// Command wrapper adalah fail-closed policy gate di depan nuclei
// (ROADMAP §13.1: tool pihak ketiga tidak pernah jalan "telanjang").
//
// Tanggung jawab wrapper (urutan eksekusi):
//
//  1. Verifikasi policy bundle — SHA-256 file bundle harus sama dengan
//     env POLICY_BUNDLE_SHA256. Fail-closed: env hilang, file hilang,
//     atau hash mismatch = REJECT, nuclei tidak pernah dieksekusi.
//  2. Terapkan budget sederhana dari bundle — max_requests dan
//     rate_limit_rps di-map ke flag -rate-limit nuclei dan ke deadline
//     eksekusi (max_requests / rate_limit_rps + grace); lewat deadline,
//     nuclei di-kill (stop condition "request budget habis", §10).
//  3. Eksekusi nuclei sebagai subprocess dengan argumen TERBATAS —
//     target dari argumen posisional wrapper (diteruskan ke nuclei
//     sebagai -target; nuclei tidak menerima target posisional),
//     -t <path templates ter-bake>, -rate-limit dari bundle, -duc
//     (disable update check, lihat peringatan template di bawah),
//     -jsonl, -o output file. Tidak ada pass-through argumen mentah;
//     tidak ada shell (os/exec langsung → tidak bisa argumen injection).
//  4. Parse output JSON minimal → tulis validation-result.json dengan
//     status "observed" + provenance (§13.1: tanpa langkah ini, output
//     tool jadi finding ilegal yang membypass finding lifecycle §26).
//
// PERINGATAN TEMPLATE PINNING (§13.1): nuclei templates adalah supply chain
// vector. Template DI-BAKE ke image saat build pada tag terpin
// (ARG NUCLEI_TEMPLATES_TAG di Dockerfile) dan TIDAK PERNAH diunduh atau
// di-update saat runtime (flag -duc). Wrapper MENOLAK jalan (exit 2) bila
// direktori template (default /nuclei-templates) tidak ada atau tidak
// memuat satu .yaml pun — bukti bahwa scan hanya berjalan dengan template
// ter-bake, bukan hasil download runtime. Hasil "vulnerable" dari tool
// tetap observation — Hermes yang menafsirkan (§17).
//
// Exit code:
//
//	0 = validation-result.json berhasil ditulis
//	1 = kegagalan eksekusi nuclei (tanpa result ditulis)
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
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	validatorID      = "tool-nuclei"
	validatorVersion = "0.1.0"

	// toolName / toolVersion untuk provenance evidence (§13.1).
	// HARUS sama dengan pin di runtimes/docker/images/tool-nuclei/Dockerfile —
	// ganti keduanya bersamaan.
	toolName    = "nuclei"
	toolVersion = "v3.11.1"

	// envBundleSHA256 menyimpan hex SHA-256 yang diharapkan untuk file
	// policy bundle (di-set oleh control plane saat menjalankan container).
	envBundleSHA256 = "POLICY_BUNDLE_SHA256"

	// defaultTemplatesDir adalah lokasi template ter-bake di image
	// (di-COPY dari stage "templates" Dockerfile saat build, §13.1).
	defaultTemplatesDir = "/nuclei-templates"

	// templatesVersionFile berisi tag nuclei-templates terpin yang
	// ditulis Dockerfile saat bake; dibaca wrapper untuk provenance.
	templatesVersionFile = ".hermes-templates-version"

	// Nama file output mentah nuclei, diletakkan bersebelahan dengan
	// validation-result.json dan dirujuk sebagai evidence ref.
	rawOutputName = "nuclei-output.json"

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

// validationResult adalah kontrak Docker Execution Contract (§17).
// Status selalu "observed": tool scanner tidak boleh menetapkan status
// vulnerability final (§17 — Hermes yang menafsirkan).
type validationResult struct {
	TaskID       string            `json:"task_id"`
	Validator    validatorIdentity `json:"validator"`
	Status       string            `json:"status"`
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
	TemplatesVersion string `json:"templates_version,omitempty"`
}

func failClosed(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "tool-nuclei wrapper: fail-closed: %s\n", fmt.Sprintf(format, args...))
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

// hostPort menormalkan target menjadi "host:port".
//
// Catatan MVP: scope matching di wrapper sengaja sederhana (exact match).
// Matcher lengkap (hostname parsing, DNS, private IP, redirect) adalah
// tanggung jawab control plane + hermes-proxy (§8, §11). Wrapper adalah
// lapisan pertahanan kedua, bukan pengganti.
func hostPort(target string) (string, string, error) {
	if strings.Contains(target, "://") {
		// URL lengkap: https://host:port/path — pakai parser URL net/url,
		// bukan substring matching (§8: gunakan parser yang benar).
		u, err := url.Parse(target)
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
	// Bentuk host[:port] tanpa scheme — default https:443 (asumsi nuclei).
	host, port, found := strings.Cut(target, ":")
	host = strings.TrimSuffix(host, "/")
	if host == "" {
		return "", "", errors.New("target kosong")
	}
	if !found || port == "" {
		port = "443"
	}
	return host, port, nil
}

// inScope mengecek host:port terhadap allowed_hosts.
// Entry "host:port" cocok exact; entry "host" (tanpa port) hanya cocok
// untuk port default 443/80 — port non-default wajib dinyatakan eksplisit.
func inScope(bundle *policyBundle, target string) error {
	host, port, err := hostPort(target)
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
	return fmt.Errorf("target %s (host %s port %s) di luar allowed_hosts bundle — scope check gagal (§8)", target, host, port)
}

// verifyTemplates memastikan template ter-bake benar-benar tersedia sebelum
// nuclei dieksekusi (§13.1). Fail-closed: path tidak ada, bukan direktori/
// file .yaml, atau direktori tidak memuat satu .yaml/.yml pun = REJECT —
// scan tanpa template ter-bake dilarang karena itu tanda nuclei akan mencoba
// mengunduh template saat runtime. Path boleh direktori ATAU satu file
// template .yaml/.yml (semantik flag -t nuclei). Mengembalikan versi
// template terpin untuk provenance (cari templatesVersionFile di path/dir
// dan maksimal 6 level di atasnya; "unknown" bila tidak ketemu).
func verifyTemplates(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("template ter-bake tidak ada di %s — image tanpa template / mount salah, tolak jalan (§13.1): %w", path, err)
	}
	found := false
	if info.IsDir() {
		walkErr := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
				found = true
				return fs.SkipAll // cukup satu template untuk membuktikan bake
			}
			return nil
		})
		if walkErr != nil {
			return "", fmt.Errorf("direktori template tidak bisa dibaca: %s — %w", path, walkErr)
		}
		if !found {
			return "", fmt.Errorf("direktori template kosong (tidak ada .yaml): %s — scan tanpa template ter-bake dilarang (§13.1)", path)
		}
	} else {
		name := filepath.Base(path)
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return "", fmt.Errorf("path template bukan direktori maupun file .yaml: %s — tolak jalan (§13.1)", path)
		}
		found = true
	}
	version := ""
	lookup := path
	if !info.IsDir() {
		lookup = filepath.Dir(path)
	}
	for i := 0; i < 6 && version == ""; i++ {
		if data, readErr := os.ReadFile(filepath.Join(lookup, templatesVersionFile)); readErr == nil {
			version = strings.TrimSpace(string(data))
		} else {
			lookup = filepath.Dir(lookup)
		}
	}
	if version == "" {
		fmt.Fprintf(os.Stderr, "tool-nuclei wrapper: peringatan: file versi template tidak terbaca, provenance templates_version=unknown\n")
		version = "unknown"
	}
	return version, nil
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

// countEvents melakukan parse JSONL minimal atas output nuclei:
// tiap baris harus JSON object valid; hasilnya jumlah event.
// Parsing detail (template-id, host, dsb.) adalah tugas normalisasi
// evidence di control plane — wrapper hanya memastikan output terbaca.
func countEvents(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return count, fmt.Errorf("baris output nuclei bukan JSON valid (offset baris %d): %w", count+1, err)
		}
		count++
	}
	return count, nil
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
	nucleiBin := flag.String("nuclei", "/usr/bin/nuclei", "path binary nuclei")
	templatesDir := flag.String("templates", defaultTemplatesDir, "path direktori atau file .yaml templates ter-bake (wajib ada, §13.1)")
	flag.Parse()

	// Target WAJIB satu argumen posisional — argumen lain tidak diteruskan.
	args := flag.Args()
	if len(args) != 1 {
		return failClosed("harus tepat satu target sebagai argumen posisional, dapat: %d", len(args))
	}
	target := args[0]

	// 1. Fail-closed: tanpa env hash, bundle tidak dianggap terverifikasi.
	expectedHex := os.Getenv(envBundleSHA256)
	bundle, err := verifyBundle(*bundlePath, expectedHex)
	if err != nil {
		return failClosed("%v", err)
	}

	// 1b. Scope check kedua (control plane tetap gate pertama, §8).
	if err := inScope(bundle, target); err != nil {
		return failClosed("%v", err)
	}

	// 1c. Template ter-bake wajib ada & berisi .yaml — fail-closed sebelum
	// nuclei dieksekusi (§13.1: scan hanya boleh jalan dengan template
	// ter-bake saat build, bukan hasil download runtime).
	templatesVersion, err := verifyTemplates(*templatesDir)
	if err != nil {
		return failClosed("%v", err)
	}
	fmt.Fprintf(os.Stderr, "tool-nuclei wrapper: templates ter-bake di %s (versi %s)\n", *templatesDir, templatesVersion)

	// Task ID untuk provenance result.
	taskID, err := loadTaskID(*taskPath)
	if err != nil {
		return failClosed("%v", err)
	}

	// 2. Budget sederhana dari bundle: pada rate_limit_rps request/detik,
	// eksekusi lebih lama dari max_requests/rate_limit_rps (+grace) berarti
	// budget habis → kill proses (stop condition §10). Ini lapisan
	// pertahanan; budget presisi per-request tetap di hermes-proxy (§11).
	budgetSeconds := bundle.MaxRequests/bundle.RateLimitRPS + budgetGraceSeconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(budgetSeconds)*time.Second)
	defer cancel()

	// 3. Eksekusi nuclei dengan argumen TERBATAS (whitelist, bukan passthrough).
	// SEMUA flag WAJIB mendahului target: nuclei (goflags) berhenti mem-parse
	// pada argumen non-flag pertama dan membuang sisanya (target tidak
	// diterima sebagai posisional, hanya via flag -target).
	rawOutPath := filepath.Join(filepath.Dir(*outPath), rawOutputName)
	cmdArgs := []string{
		"-target", target,
		"-t", *templatesDir, // template ter-bake — tidak ada download runtime (§13.1)
		"-rate-limit", fmt.Sprintf("%d", bundle.RateLimitRPS),
		"-duc",   // disable update check — template tidak pernah di-update saat runtime (§13.1)
		"-jsonl", // output JSONL (flag -json dihapus sejak nuclei v3.3)
		"-o", rawOutPath,
	}
	cmd := exec.CommandContext(ctx, *nucleiBin, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmdErr := cmd.Run()

	budgetExceeded := errors.Is(cmdErr, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmdErr != nil && !budgetExceeded {
		// Nuclei gagal (binary rusak, template tidak ter-mount, dsb.) —
		// jangan tulis result yang menyesatkan; laporkan via exit code.
		return failClosed("nuclei gagal dieksekusi: %v", cmdErr)
	}
	if budgetExceeded {
		fmt.Fprintf(os.Stderr, "tool-nuclei wrapper: budget stop — deadline %ds tercapai, nuclei di-kill (§10 request budget habis)\n", budgetSeconds)
	}

	// 4. Parse output JSON minimal → validation-result.json.
	evidenceRefs := []string{}
	if _, statErr := os.Stat(rawOutPath); statErr == nil {
		events, parseErr := countEvents(rawOutPath)
		if parseErr != nil {
			// Output ada tapi korup: bukan alasan menelanjudkan evidence —
			// tetap dirujuk agar adapter bisa menandai evidence rusak.
			fmt.Fprintf(os.Stderr, "tool-nuclei wrapper: peringatan parse output: %v\n", parseErr)
		} else {
			fmt.Fprintf(os.Stderr, "tool-nuclei wrapper: output nuclei terbaca, %d event\n", events)
		}
		evidenceRefs = append(evidenceRefs, rawOutPath)
	} else if budgetExceeded {
		fmt.Fprintln(os.Stderr, "tool-nuclei wrapper: tidak ada output nuclei (budget tercapai sebelum hasil pertama)")
	}

	res := validationResult{
		TaskID:       taskID,
		Validator:    validatorIdentity{ID: validatorID, Version: validatorVersion},
		Status:       "observed", // tool tidak pernah menyatakan "vulnerable confirmed" (§17)
		EvidenceRefs: evidenceRefs,
		Provenance: provenance{
			Tool:             toolName,
			ToolVersion:      toolVersion,
			TemplatesVersion: templatesVersion, // versi template ter-bake (§13.1)
		},
	}
	if err := writeResult(*outPath, res); err != nil {
		return failClosed("gagal menulis validation-result.json: %v", err)
	}
	fmt.Fprintf(os.Stderr, "tool-nuclei wrapper: result ditulis ke %s\n", *outPath)
	return 0
}

func main() {
	os.Exit(run())
}
