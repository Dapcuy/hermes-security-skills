// Package dockerx adalah Docker runtime adapter control plane Hermes
// (ROADMAP §15, §16, §18, §20).
//
// Mengapa wrapper `docker` CLI via os/exec, bukan Docker SDK/API:
//
//  1. Stdlib only — project melarang dependency eksternal; SDK Docker
//     menarik graph dependency besar yang harus di-review (TCB, §20).
//  2. Trust boundary (§20): control plane Go adalah TCB — SATU-SATUNYA
//     komponen yang memegang akses Docker. Hermes (LLM) TIDAK PERNAH
//     menjalankan docker secara langsung (§12, §20, §4.4); ia hanya
//     meminta capability lewat control plane, dan control plane inilah
//     yang memanggil wrapper ini dengan baseline security yang sudah
//     fixed/fail-closed (§15) — Hermes tidak bisa memilih flag sendiri.
//  3. exec langsung tanpa shell → tidak ada quoting shell; os/exec
//     melakukan escaping argumen Windows (syscall.EscapeArg) sendiri,
//     dan path bind mount Windows (C:\...) diteruskan apa adanya.
//
// Semua container dijalankan dengan baseline §15 (read-only, cap-drop ALL,
// no-new-privileges, pids/mem/cpu limit, tmpfs /tmp) dan §16 (--network
// none). Lifecycle ephemeral §18: run --rm + pembersihan paksa `docker rm -f`
// pada setiap kegagalan — tidak ada container yang tertinggal.
package dockerx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Konvensi path in-container lintas platform (ROADMAP §19).
const (
	ContainerInputDir  = "/workspace/input"
	ContainerOutputDir = "/workspace/output"
)

// Label adapter (§18 / kill switch §10):
//   - hermes.managed=true : container dikelola adapter ini
//   - hermes.role         : validator | proxy (kill switch menyasar per-case,
//     jadi role berbeda tetap ter-kill bila label case-nya sama)
//   - hermes.case         : WAJIB pada setiap run — tanpa ini run ditolak,
//     agar `abort --case` selalu bisa menemukan containernya.
const (
	LabelManaged = "hermes.managed"
	LabelRole    = "hermes.role"
	LabelCase    = "hermes.case"

	labelManagedValue = "hermes.managed=true"
	labelRoleValue    = "hermes.role=validator"

	defaultDockerBin = "docker"
)

// Execer menjalankan satu invocation `docker <args...>`.
// Abstraksi ini memungkinkan fake exec helper pada unit test tanpa
// Docker sungguhan; produksi memakai CLIExecer.
type Execer interface {
	// Exec mengembalikan stdout (stderr digabung untuk diagnosa).
	// Error mencakup exit code non-zero dan kegagalan start proses.
	Exec(ctx context.Context, args ...string) ([]byte, error)
}

// CLIExecer exec binary docker sungguhan via os/exec (tanpa shell).
type CLIExecer struct {
	Bin string // kosong = "docker" (di-resolve lewat PATH)
}

func (c CLIExecer) bin() string {
	if c.Bin == "" {
		return defaultDockerBin
	}
	return c.Bin
}

func (c CLIExecer) Exec(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.bin(), args...)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return []byte(out.String()), fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return []byte(out.String()), nil
}

// defaultExecer dapat ditimpa fake exec helper pada unit test
// (test berada dalam package yang sama).
var defaultExecer Execer = CLIExecer{}

// ------------------------------------------------------------------ Available

type dockerVersionJSON struct {
	Client *struct {
		Version string `json:"Version"`
	} `json:"Client"`
	Server *struct {
		Version string `json:"Version"`
	} `json:"Server"`
}

// Available memeriksa Docker engine tersedia: `docker version --format json`,
// lalu parse versi server. Server null (daemon mati / tidak terpasang)
// = error eksplisit — fail-closed.
func Available() error { return available(defaultExecer) }

func available(x Execer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := x.Exec(ctx, "version", "--format", "json")
	if err != nil {
		return fmt.Errorf("dockerx: docker version gagal (apakah Docker terpasang dan daemon berjalan?): %w", err)
	}
	var v dockerVersionJSON
	if err := json.Unmarshal(trimJSON(out), &v); err != nil {
		return fmt.Errorf("dockerx: output docker version tidak valid: %w", err)
	}
	if v.Server == nil || v.Server.Version == "" {
		return errors.New("dockerx: docker CLI ada tetapi server engine tidak terjangkau (daemon mati?)")
	}
	return nil
}

// ServerVersion mengembalikan versi Docker server (untuk audit/doctor).
func ServerVersion() (string, error) { return serverVersion(defaultExecer) }

func serverVersion(x Execer) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := x.Exec(ctx, "version", "--format", "json")
	if err != nil {
		return "", err
	}
	var v dockerVersionJSON
	if err := json.Unmarshal(trimJSON(out), &v); err != nil {
		return "", fmt.Errorf("dockerx: output docker version tidak valid: %w", err)
	}
	if v.Server == nil || v.Server.Version == "" {
		return "", errors.New("dockerx: server engine tidak terjangkau")
	}
	return v.Server.Version, nil
}

// trimJSON memotong noise di sekitar objek JSON (sebagian build CLI
// mencetak warning ke stdout sebelum payload).
func trimJSON(b []byte) []byte {
	s := strings.TrimSpace(string(b))
	if i := strings.Index(s, "{"); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndex(s, "}"); j >= 0 && j < len(s)-1 {
		s = s[:j+1]
	}
	return []byte(s)
}

// ------------------------------------------------------------------- RunSpec

// RunSpec parameter satu eksekusi validator ephemeral (§17/§18).
type RunSpec struct {
	// Image ref: name:tag atau name@digest (§14). Wajib.
	Image string
	// Cmd: argumen SETELAH image. Image validator distroless memakai
	// ENTRYPOINT (§13), jadi Cmd berisi flag validator, bukan binary.
	Cmd []string
	// InputDir/OutputDir: path host ABSOLUTE (wajib, diverifikasi) yang
	// di-mount read-only / read-write ke /workspace/{input,output} (§19).
	InputDir  string
	OutputDir string
	// Env pasangan KEY=VALUE yang di-inject (-e). Divalidasi fail-closed.
	Env []string
	// Labels tambahan. WAJIB berisi hermes.case=<id> (kill switch §10).
	// hermes.managed dan hermes.role di-set adapter dan tidak boleh dioverride.
	Labels map[string]string
	// Timeout wajib > 0 (§15: timeout; §36: dikalibrasi lintas platform).
	Timeout time.Duration
	// Name --name container; divalidasi terhadap charset Docker.
	Name string
}

// validContainerName: charset nama container Docker
// [a-zA-Z0-9][a-zA-Z0-9_.-]*.
var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// validEnvKey: nama environment variable POSIX-ish.
var validEnvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// SanitizeName mengubah string menjadi nama container yang valid
// (karakter di luar [a-zA-Z0-9_.-] menjadi '-', dipotong 48 karakter).
func SanitizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		out = "x"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

// buildRunArgs menyusun argumen `docker run` lengkap dengan baseline
// security §15 + network none §16. Pure function — mudah di-unit-test.
func buildRunArgs(spec RunSpec) ([]string, error) {
	switch {
	case strings.TrimSpace(spec.Image) == "":
		return nil, errors.New("dockerx: RunSpec.Image wajib diisi")
	case strings.TrimSpace(spec.Image) != spec.Image:
		return nil, errors.New("dockerx: RunSpec.Image tidak boleh beri spasi di tepi")
	case strings.ContainsAny(spec.Image, " \t\n"):
		return nil, fmt.Errorf("dockerx: RunSpec.Image %q tidak valid (spasi bukan bagian image ref)", spec.Image)
	case spec.Name == "" || !validContainerName.MatchString(spec.Name):
		return nil, fmt.Errorf("dockerx: RunSpec.Name %q tidak valid (harus cocok [a-zA-Z0-9][a-zA-Z0-9_.-]*)", spec.Name)
	case spec.Timeout <= 0:
		return nil, errors.New("dockerx: RunSpec.Timeout wajib > 0 (fail-closed: container tanpa timeout ditolak)")
	case !filepath.IsAbs(spec.InputDir):
		return nil, fmt.Errorf("dockerx: RunSpec.InputDir harus path absolut, dapat %q", spec.InputDir)
	case !filepath.IsAbs(spec.OutputDir):
		return nil, fmt.Errorf("dockerx: RunSpec.OutputDir harus path absolut, dapat %q", spec.OutputDir)
	}
	caseID := spec.Labels[LabelCase]
	if caseID == "" {
		return nil, fmt.Errorf("dockerx: RunSpec.Labels wajib berisi %s=<case-id> (prasyarat kill switch §10)", LabelCase)
	}

	args := make([]string, 0, 32+len(spec.Cmd)+2*len(spec.Env)+2*len(spec.Labels))
	args = append(args, "run", "--rm")
	args = append(args, "--name", spec.Name)

	// --- Baseline security §15 ---
	args = append(args, "--network", "none")                        // §16 — deny-by-default
	args = append(args, "--read-only")                              // rootfs read-only
	args = append(args, "--cap-drop", "ALL")                        // tanpa capability
	args = append(args, "--security-opt", "no-new-privileges:true") // tanpa eskalasi
	args = append(args, "--pids-limit", "64")                       // anti fork-bomb
	args = append(args, "--memory", "512m")                         // mem limit
	args = append(args, "--cpus", "1.0")                            // cpu limit
	// /tmp writable kecil walau rootfs read-only.
	args = append(args, "--tmpfs", "/tmp:rw,size=16m")

	// --- Label adapter + caller ---
	args = append(args, "--label", labelManagedValue)
	args = append(args, "--label", labelRoleValue)
	args = append(args, "--label", LabelCase+"="+caseID)
	// Label tambahan (diurutkan agar deterministik untuk audit/test);
	// label reserved tidak boleh dioverride.
	extra := make([]string, 0, len(spec.Labels))
	for k := range spec.Labels {
		if k == LabelCase || k == LabelManaged || k == LabelRole {
			continue
		}
		if k == "" || strings.ContainsAny(k, " \t=") {
			return nil, fmt.Errorf("dockerx: label key %q tidak valid", k)
		}
		if strings.ContainsAny(spec.Labels[k], " \t\n") {
			return nil, fmt.Errorf("dockerx: label value %q tidak valid", spec.Labels[k])
		}
		extra = append(extra, k)
	}
	sort.Strings(extra)
	for _, k := range extra {
		args = append(args, "--label", k+"="+spec.Labels[k])
	}

	// --- Mount terkontrol (§15: controlled filesystem mounts, §19) ---
	args = append(args, "-v", spec.InputDir+":"+ContainerInputDir+":ro")
	args = append(args, "-v", spec.OutputDir+":"+ContainerOutputDir)

	// --- Env terkontrol ---
	for _, e := range spec.Env {
		if !validEnvKey.MatchString(e) {
			return nil, fmt.Errorf("dockerx: env %q tidak valid (harus KEY=VALUE, KEY=[A-Za-z_][A-Za-z0-9_]*)", e)
		}
		args = append(args, "-e", e)
	}

	// --- Image + Cmd (di akhir, urutan wajib) ---
	args = append(args, spec.Image)
	args = append(args, spec.Cmd...)
	return args, nil
}

// Run menjalankan container ephemeral sesuai spec (baseline §15/§16),
// menunggu sampai selesai atau timeout, lalu mengembalikan output gabungan.
//
// Timeout memakai exec.CommandContext: saat ctx habis, proses CLI docker
// di-kill — TAPI container di daemon tetap berjalan (client terputus
// tidak menghentikan container). Karena itu, pada timeout maupun exit
// error, adapter SELALU menjalankan `docker rm -f <name>` (§18 lifecycle:
// create → destroy tanpa leak); error cleanup "sudah hilang" diabaikan.
func Run(ctx context.Context, spec RunSpec) ([]byte, error) {
	return runWith(defaultExecer, ctx, spec)
}

func runWith(x Execer, ctx context.Context, spec RunSpec) ([]byte, error) {
	args, err := buildRunArgs(spec)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	out, runErr := x.Exec(runCtx, args...)
	if runErr != nil {
		// Pembersihan paksa (kill switch kecil per-container) — best effort,
		// error asli run yang dikembalikan.
		removeContainer(x, spec.Name)
		return out, fmt.Errorf("dockerx: container %s gagal: %w", spec.Name, runErr)
	}
	return out, nil
}

// removeContainer `docker rm -f <name>` dengan context terpisah (parent
// mungkin sudah cancel/timeout). Semua error diabaikan: container bisa
// saja sudah terhapus oleh --rm.
func removeContainer(x Execer, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = x.Exec(ctx, "rm", "-f", name) //nolint:errcheck // best-effort cleanup
}

// ---------------------------------------------------------------- ImageExists

// ImageExists memeriksa image sudah ada di daemon lokal (tanpa pull).
// Dipakai validate untuk fail-closed SEBELUM run dengan pesan yang jelas.
func ImageExists(ref string) (bool, error) { return imageExists(defaultExecer, ref) }

func imageExists(x Execer, ref string) (bool, error) {
	if strings.TrimSpace(ref) == "" {
		return false, errors.New("dockerx: ref image kosong")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := x.Exec(ctx, "image", "inspect", ref); err != nil {
		return false, nil // tidak ada = bukan error eksekusi
	}
	return true, nil
}

// -------------------------------------------------------------- RemoveByLabel

// RemoveByLabel menghentikan paksa (`docker rm -f`) SEMUA container yang
// punya label `label` (format "key=value", mis. "hermes.case=demo-1") —
// dasar kill switch `hermes-security abort --case` (§10, §18: container
// yang berjalan saat abort wajib di-kill dan dibersihkan).
// Mengembalikan jumlah container yang di-remove.
func RemoveByLabel(label string) (int, error) { return removeByLabel(defaultExecer, label) }

func removeByLabel(x Execer, label string) (int, error) {
	if !validLabelSelector(label) {
		return 0, fmt.Errorf("dockerx: label selector %q tidak valid (harus key=value tanpa spasi)", label)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := x.Exec(ctx, "ps", "-aq", "--filter", "label="+label)
	if err != nil {
		return 0, fmt.Errorf("dockerx: cari container label %s: %w", label, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0, nil
	}
	// rm satu per satu: `docker rm -f` multi-id berhenti pada id pertama
	// yang sudah hilang; per-container memberi hasil terbaik dan
	// toleran terhadap container yang sudah mati sendiri (--rm).
	removed := 0
	for _, id := range fields {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if _, err := x.Exec(rmCtx, "rm", "-f", id); err == nil {
			removed++
		}
		rmCancel()
	}
	return removed, nil
}

func validLabelSelector(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\n") {
		return false
	}
	k, v, ok := strings.Cut(s, "=")
	return ok && k != "" && v != ""
}
