// Command wrapper adalah fail-closed policy gate di depan nmap
// (ROADMAP §13.1: tool pihak ketiga tidak pernah jalan "telanjang").
//
// Tanggung jawab wrapper (urutan eksekusi):
//
//	1. Verifikasi policy bundle — SHA-256 file bundle harus sama dengan
//	   env POLICY_BUNDLE_SHA256. Fail-closed: env hilang, file hilang,
//	   atau hash mismatch = REJECT, nmap tidak pernah dieksekusi.
//	2. Scope check target — target (host) WAJIB cocok exact dengan host
//	   pada bundle.allowed_hosts (§8). Target bentuk CIDR/range/wildcard/
//	   multi-host di-tolak keras — hanya SATU host eksplisit per run.
//	3. Terapkan budget dari bundle — budget→max ports: jumlah port pada
//	   --ports wajib <= bundle.max_requests (fail-closed); rate_limit_rps
//	   diteruskan sebagai --max-rate. Keduanya membatasi agresivitas scan
//	   (tool mass-scanner agresif secara default, §13.1).
//	4. Eksekusi nmap sebagai subprocess dengan argumen TERBATAS — mode
//	   WAJIB -sT (connect scan: tidak butuh NET_RAW, kompatibel
//	   cap_drop: ALL). Flag -sS/-sU/-sO/-sA (raw socket) TIDAK ADA jalur
//	   masuk: tidak ada pass-through argumen, argumen posisional ekstra
//	   ditolak (exit 2), dan argv yang dibangun diverifikasi ulang
//	   terhadap whitelist sebelum exec (defense in depth). Tidak ada
//	   shell (os/exec langsung → tidak bisa argumen injection). nmap juga
//	   TIDAK diberi stdin (cmd.Stdin = nil → /dev/null).
//	5. Parse output greppable (-oG) → tulis validation-result.json dengan
//	   status "observed" + provenance (§13.1: tanpa langkah ini, output
//	   tool jadi finding ilegal yang membypass finding lifecycle §26).
//
// PERINGATAN (§13.1): banyak program bug bounty MELARANG port scanning
// agresif. Risk classification port scan = HIGH (§8) → WAJIB approval
// eksplisit, scope eksplisit per-host, dan budget ketat. Wrapper adalah
// lapisan pertahanan kedua; scope validation utama tetap di control plane
// (§8).
//
// CATATAN DEVIASI KECIL: whitelist direncanakan memuat --no-stdin, namun
// nmap 7.93 TIDAK memiliki opsi tersebut (diverifikasi: "unrecognized
// option '--no-stdin'"). Tujuan yang sama dicapai dengan cmd.Stdin = nil
// (nmap membaca /dev/null, mustahil menerima input interaktif).
//
// Exit code:
//
//	0 = validation-result.json berhasil ditulis
//	1 = kegagalan eksekusi nmap (tanpa result ditulis)
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
	"strconv"
	"strings"
	"time"
)

const (
	validatorID      = "tool-nmap"
	validatorVersion = "0.1.0"

	// toolName / toolVersion untuk provenance evidence (§13.1).
	// HARUS sama dengan pin ARG NMAP_VERSION di
	// runtimes/docker/images/tool-nmap/Dockerfile — ganti keduanya bersamaan.
	toolName    = "nmap"
	toolVersion = "7.93+dfsg1-1"

	// envBundleSHA256 menyimpan hex SHA-256 yang diharapkan untuk file
	// policy bundle (di-set oleh control plane saat menjalankan container).
	envBundleSHA256 = "POLICY_BUNDLE_SHA256"

	// Nama file output mentah nmap (greppable), diletakkan bersebelahan
	// dengan validation-result.json dan dirujuk sebagai evidence ref.
	rawOutputName = "nmap-output.gnmap"

	// scanMode adalah satu-satunya mode scan yang di-whitelist:
	// -sT connect scan — TIDAK butuh NET_RAW, kompatibel cap_drop: ALL.
	scanMode = "-sT"
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
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
}

func failClosed(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "tool-nmap wrapper: fail-closed: %s\n", fmt.Sprintf(format, args...))
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

// normalizeTarget menormalkan target dan MENOLAK bentuk yang bukan satu
// host eksplisit: CIDR ("/"), range ("-"/","), wildcard ("*"), IPv6/port
// (":"), spasi, atau flag injection (awalan "-"). Scan multi-host/subnet
// tidak pernah masuk lewat wrapper — hanya SATU host per run.
func normalizeTarget(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", errors.New("target kosong")
	}
	if strings.HasPrefix(t, "-") {
		return "", fmt.Errorf("target tidak boleh diawali '-' (flag injection): %q", raw)
	}
	if strings.ContainsAny(t, "/,*@ \t") {
		return "", fmt.Errorf("target berbentuk CIDR/range/wildcard tidak didukung — hanya satu host eksplisit: %q", raw)
	}
	if strings.Contains(t, ":") {
		return "", fmt.Errorf("target dengan ':' (IPv6 atau host:port) tidak didukung — berikan host saja: %q", raw)
	}
	return strings.ToLower(strings.TrimSuffix(t, ".")), nil
}

// hostInScope mengecek target terhadap allowed_hosts.
// Entry "host:port" dibandingkan pada BAGIAN HOST-nya; entry "host" tanpa
// port juga cocok (port-level allowlist adalah tanggung jawab control
// plane + hermes-proxy §8/§11 — wrapper membatasi host + jumlah port via
// budget). Exact match, case-insensitive; entry wildcard diabaikan.
func hostInScope(bundle *policyBundle, target string) error {
	for _, entry := range bundle.AllowedHosts {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if strings.Contains(entry, "*") {
			continue
		}
		host := entry
		if h, _, ok := strings.Cut(entry, ":"); ok && h != "" {
			host = h
		}
		if host == target {
			return nil
		}
	}
	return fmt.Errorf("target %s di luar allowed_hosts bundle — hanya host in-scope eksplisit yang boleh di-scan (§8)", target)
}

// validatePortSpec memvalidasi spec port nmap ("-p") dan menerapkan
// budget→max ports: total jumlah port (range di-expand) wajib <=
// bundle.max_requests. Format diterima: "80", "1-1000", "80,443,8080".
// Fail-closed: format aneh, port di luar 1-65535, atau melebihi budget
// = REJECT. Mengembalikan spec yang sama (untuk diteruskan ke nmap).
func validatePortSpec(spec string, maxPorts int) (string, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return "", errors.New("--ports wajib diisi (wrapper tidak pernah menjalankan scan port-default tanpa persetujuan eksplisit)")
	}
	total := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", fmt.Errorf("spec port tidak valid: %q", spec)
		}
		lo, hi := part, part
		if l, h, ok := strings.Cut(part, "-"); ok {
			lo, hi = l, h
		}
		loN, errLo := strconv.Atoi(lo)
		hiN, errHi := strconv.Atoi(hi)
		if errLo != nil || errHi != nil || loN < 1 || hiN > 65535 || loN > hiN {
			return "", fmt.Errorf("spec port tidak valid: %q (bagian %q)", spec, part)
		}
		total += hiN - loN + 1
	}
	if total > maxPorts {
		return "", fmt.Errorf("jumlah port %d melebihi budget bundle.max_requests=%d — perkecil -p atau minta budget lebih (§10)", total, maxPorts)
	}
	return s, nil
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

// checkArgvWhitelist adalah defense-in-depth: argv final yang dibangun
// wrapper diverifikasi ulang — mode scan hanya boleh -sT; flag -sS/-sU/
// -sO/-sA (raw socket / lainnya) atau flag di luar whitelist apa pun
// harusnya mustahil muncul (tidak ada pass-through), dan jika muncul
// (kesalahan edit di masa depan) wrapper MENOLAK jalan.
func checkArgvWhitelist(argv []string) error {
	allowed := map[string]bool{
		scanMode:    true, // -sT
		"-p":        true,
		"--max-rate": true,
		"-oG":       true,
	}
	for _, a := range argv {
		if strings.HasPrefix(a, "-") && !allowed[a] {
			return fmt.Errorf("argv berisi flag di luar whitelist: %q (mode selain -sT seperti -sS/-sU/-sO/-sA dilarang keras — tanpa NET_RAW, §13.1)", a)
		}
	}
	return nil
}

// parseGreppable membaca output -oG nmap dan menormalkan port open menjadi
// observations. Format baris:
//
//	Host: 192.168.65.2 ()	Status: Up
//	Host: 192.168.65.2 ()	Ports: 8080/open/tcp//http-alt///, 8081/closed/tcp///,  ...
func parseGreppable(path string) ([]observation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var obs []observation
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "Host:") {
			continue
		}
		hostPart, rest, ok := strings.Cut(strings.TrimPrefix(line, "Host:"), "\t")
		if !ok {
			continue
		}
		// hostPart: "1.2.3.4 ()" atau "1.2.3.4 (reverse.name)" → ambil IP.
		host := strings.TrimSpace(strings.Fields(strings.TrimSpace(hostPart))[0])
		if !strings.HasPrefix(rest, "Ports:") {
			continue
		}
		for _, tok := range strings.Split(strings.TrimPrefix(rest, "Ports:"), ",") {
			fields := strings.Split(strings.TrimSpace(tok), "/")
			if len(fields) < 2 {
				continue
			}
			port, err := strconv.Atoi(fields[0])
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			if fields[1] != "open" {
				continue
			}
			obs = append(obs, observation{Type: "open_port", Detail: fmt.Sprintf("%s:%d", host, port)})
		}
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

// portSpec adalah flag bersama untuk --ports dan -p (semantik sama dengan
// -p nmap): menolak dua nilai berbeda pada flag yang sama.
type portSpec struct{ v string }

func (p *portSpec) String() string { return p.v }
func (p *portSpec) Set(s string) error {
	if p.v != "" && p.v != s {
		return fmt.Errorf("--ports/-p diberikan dua kali dengan nilai berbeda: %q vs %q", p.v, s)
	}
	p.v = s
	return nil
}

func run() int {
	bundlePath := flag.String("bundle", "", "path policy bundle (wajib, hash-verified via POLICY_BUNDLE_SHA256)")
	taskPath := flag.String("input", "/workspace/input/validation-task.json", "path validation-task.json")
	outPath := flag.String("output", "/workspace/output/validation-result.json", "path validation-result.json")
	nmapBin := flag.String("nmap", "/usr/bin/nmap", "path binary nmap")
	// Spec port dipahami wrapper langsung (semantik -p nmap, -p/--ports
	// alias). nmap dijalankan wrapper dengan -sT, -p, --max-rate, -oG
	// saja — whitelist tertutup, flag nmap lain (mis. -sS/-sU/-sO/-sA)
	// tidak punya jalur masuk.
	var ps portSpec
	flag.Var(&ps, "ports", "spec port nmap untuk -p (WAJIB, mis. \"1-1000\" atau \"80,443\"); jumlah port wajib <= bundle.max_requests")
	flag.Var(&ps, "p", "alias --ports")
	flag.Parse()

	// Target WAJIB satu argumen posisional. Argumen posisional ekstra
	// (termasuk percobaan menyelipkan -sS/-sU/-sO/-sA lewat akhir command
	// line) = TOLAK keras — tidak ada pass-through apa pun.
	args := flag.Args()
	if len(args) < 1 {
		return failClosed("harus tepat satu target host sebagai argumen posisional, dapat: %d", len(args))
	}
	if len(args) > 1 {
		return failClosed("argumen tambahan tidak di-whitelist dan ditolak (hanya satu target; flag seperti -sS/-sU/-sO/-sA tidak bisa masuk): %q", args[1:])
	}
	target, err := normalizeTarget(args[0])
	if err != nil {
		return failClosed("%v", err)
	}

	// 1. Fail-closed: tanpa env hash, bundle tidak dianggap terverifikasi.
	expectedHex := os.Getenv(envBundleSHA256)
	bundle, err := verifyBundle(*bundlePath, expectedHex)
	if err != nil {
		return failClosed("%v", err)
	}

	// 2. Scope check target (control plane tetap gate pertama, §8).
	if err := hostInScope(bundle, target); err != nil {
		return failClosed("%v", err)
	}

	// 2b. Budget→max ports: jumlah port pada -p wajib <= max_requests.
	portSpecStr, err := validatePortSpec(ps.v, bundle.MaxRequests)
	if err != nil {
		return failClosed("%v", err)
	}

	// Task ID untuk provenance result.
	taskID, err := loadTaskID(*taskPath)
	if err != nil {
		return failClosed("%v", err)
	}

	// 3. Budget→rate: --max-rate dari bundle.rate_limit_rps. (Deadline ctx
	// tetap dipasang sebagai pengaman kedua — nmap tanpa -T4 pada range
	// port besar bisa berjalan sangat lama; grace period sama dengan pola
	// tool-nuclei.)
	budgetSeconds := bundle.MaxRequests/bundle.RateLimitRPS + 4*60
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(budgetSeconds)*time.Second)
	defer cancel()

	// 4. Eksekusi nmap dengan argumen TERBATAS (whitelist, bukan
	// passthrough): -sT WAJIB (connect scan), -p dari caller ter-validasi,
	// --max-rate dari bundle, -oG greppable. cmd.Stdin = nil → /dev/null
	// (pengganti --no-stdin yang tidak ada di nmap 7.93 — lihat CATATAN
	// DEVIASI di header).
	rawOutPath := filepath.Join(filepath.Dir(*outPath), rawOutputName)
	cmdArgs := []string{
		scanMode, // -sT — satu-satunya mode yang di-whitelist
		"-p", portSpecStr,
		"--max-rate", fmt.Sprintf("%d", bundle.RateLimitRPS),
		"-oG", rawOutPath,
		target,
	}
	if err := checkArgvWhitelist(cmdArgs); err != nil {
		return failClosed("%v", err)
	}
	cmd := exec.CommandContext(ctx, *nmapBin, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil // nmap membaca /dev/null — tidak pernah interaktif
	cmdErr := cmd.Run()

	budgetExceeded := errors.Is(cmdErr, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmdErr != nil && !budgetExceeded {
		// Nmap gagal (binary rusak, flag tidak valid, dsb.) — jangan tulis
		// result yang menyesatkan; laporkan via exit code.
		return failClosed("nmap gagal dieksekusi: %v", cmdErr)
	}
	if budgetExceeded {
		fmt.Fprintf(os.Stderr, "tool-nmap wrapper: budget stop — deadline %ds tercapai, nmap di-kill (§10 request budget habis)\n", budgetSeconds)
	}

	// 5. Parse output greppable → validation-result.json.
	evidenceRefs := []string{}
	observations := []observation{}
	if _, statErr := os.Stat(rawOutPath); statErr == nil {
		obs, parseErr := parseGreppable(rawOutPath)
		if parseErr != nil {
			// Output ada tapi korup: tetap dirujuk agar adapter bisa
			// menandai evidence rusak.
			fmt.Fprintf(os.Stderr, "tool-nmap wrapper: peringatan parse output: %v\n", parseErr)
		}
		observations = append(observations, obs...)
		evidenceRefs = append(evidenceRefs, rawOutPath)
	} else if budgetExceeded {
		fmt.Fprintln(os.Stderr, "tool-nmap wrapper: tidak ada output nmap (budget tercapai sebelum hasil pertama)")
	}
	fmt.Fprintf(os.Stderr, "tool-nmap wrapper: %d port open terobservasi\n", len(observations))

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
	fmt.Fprintf(os.Stderr, "tool-nmap wrapper: result ditulis ke %s\n", *outPath)
	return 0
}

func main() {
	os.Exit(run())
}
