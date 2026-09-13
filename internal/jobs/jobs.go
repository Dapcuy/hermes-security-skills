// Package jobs mengelola workspace job per task — lifecycle §18:
//
//	jobs/<caseID>/<taskID>/
//	  ├── input/       validation-task.json (di-mount read-only ke container)
//	  ├── output/      validation-result.json (ditulis validator)
//	  ├── artifacts/   evidence mentah yang dikumpulkan (retention §25)
//	  └── logs/        stdout/stderr container
//
// Kontrak §18: workspace adalah satu-satunya jalur data masuk/keluar
// container; container tidak pernah jadi persistent memory. Case ID bisa
// di-tandai ABORTED oleh kill switch (§10) — task baru pada case tersebut
// ditolak (fail-closed).
package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Nama file kontrak dalam workspace (§17).
const (
	TaskFile    = "validation-task.json"
	ResultFile  = "validation-result.json"
	AbortedFile = "ABORTED"
)

// validID melindungi dari path traversal — ID hanya charset aman
// (fail-closed, §4.2).
var validID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// Workspace path workspace satu task.
type Workspace struct {
	Root   string // root jobs dir (relatif atau absolut, sesuai caller)
	CaseID string
	TaskID string

	Dir          string // <root>/<case>/<task>
	InputDir     string
	OutputDir    string
	ArtifactsDir string
	LogsDir      string
}

// ValidID memeriksa case/task id aman dipakai sebagai nama direktori.
func ValidID(id string) bool {
	return validID.MatchString(id) && id != ".."
}

// Create membuat workspace jobs/<caseID>/<taskID>/{input,output,artifacts,logs}
// di bawah root (mis. repo-root "jobs" atau --jobs-dir). Idempotent:
// workspace yang sudah ada dipakai ulang.
func Create(root, caseID, taskID string) (*Workspace, error) {
	if !ValidID(caseID) {
		return nil, fmt.Errorf("jobs: case id %q tidak valid (huruf/angka/._- , maks 64)", caseID)
	}
	if !ValidID(taskID) {
		return nil, fmt.Errorf("jobs: task id %q tidak valid (huruf/angka/._- , maks 64)", taskID)
	}
	root = filepath.Clean(root)
	if filepath.IsAbs(root) && strings.TrimSpace(root) == filepath.VolumeName(root)+`\` {
		return nil, fmt.Errorf("jobs: root %q tidak valid", root)
	}
	ws := &Workspace{
		Root:         root,
		CaseID:       caseID,
		TaskID:       taskID,
		Dir:          filepath.Join(root, caseID, taskID),
		InputDir:     filepath.Join(root, caseID, taskID, "input"),
		OutputDir:    filepath.Join(root, caseID, taskID, "output"),
		ArtifactsDir: filepath.Join(root, caseID, taskID, "artifacts"),
		LogsDir:      filepath.Join(root, caseID, taskID, "logs"),
	}
	for _, d := range []string{ws.InputDir, ws.OutputDir, ws.ArtifactsDir, ws.LogsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("jobs: buat %s: %w", d, err)
		}
	}
	return ws, nil
}

// TaskPath path validation-task.json dalam workspace.
func (w *Workspace) TaskPath() string { return filepath.Join(w.InputDir, TaskFile) }

// ResultPath path validation-result.json dalam workspace.
func (w *Workspace) ResultPath() string { return filepath.Join(w.OutputDir, ResultFile) }

// ContainerLogPath path log stdout/stderr container.
func (w *Workspace) ContainerLogPath() string { return filepath.Join(w.LogsDir, "container.log") }

// WriteTask menulis task (akan di-marshal indented) ke input/validation-task.json.
// File ini yang di-mount read-only ke container (§18: mount controlled input).
func (w *Workspace) WriteTask(task any) error {
	data, err := json.MarshalIndent(task, "", "  ")
	if err != nil {
		return fmt.Errorf("jobs: marshal task: %w", err)
	}
	if err := os.WriteFile(w.TaskPath(), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("jobs: tulis %s: %w", w.TaskPath(), err)
	}
	return nil
}

// WriteLog menyimpan output container ke logs/ (bukti eksekusi §18).
func (w *Workspace) WriteLog(name string, data []byte) error {
	path := filepath.Join(w.LogsDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("jobs: tulis log %s: %w", path, err)
	}
	return nil
}

// CollectResult membaca output/validation-result.json (§18: collect result).
// File belum ada = error eksplisit (validator gagal / tidak menulis output).
func (w *Workspace) CollectResult() (map[string]any, error) {
	data, err := os.ReadFile(w.ResultPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("jobs: %s belum dihasilkan (validator gagal atau timeout?)", ResultFile)
		}
		return nil, fmt.Errorf("jobs: baca %s: %w", w.ResultPath(), err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("jobs: parse %s: %w", w.ResultPath(), err)
	}
	return result, nil
}

// Cleanup menghapus workspace (§18: destroy). Jika keepArtifacts, isi
// artifacts/ dipertahankan (evidence §25) dan hanya input/output/logs yang
// dihapus; jika tidak, seluruh direktori task dihapus — direktori case
// ikut dihapus bila menjadi kosong.
func (w *Workspace) Cleanup(keepArtifacts bool) error {
	if !strings.HasPrefix(w.Dir, filepath.Clean(w.Root)+string(os.PathSeparator)) &&
		filepath.Clean(w.Dir) != filepath.Clean(w.Root) {
		return fmt.Errorf("jobs: workspace %s di luar root %s (tolak hapus)", w.Dir, w.Root)
	}
	dirs := []string{w.InputDir, w.OutputDir, w.LogsDir}
	if !keepArtifacts {
		if err := os.RemoveAll(w.Dir); err != nil {
			return fmt.Errorf("jobs: hapus %s: %w", w.Dir, err)
		}
		// Bersihkan direktori case bila kosong (best-effort).
		caseDir := filepath.Dir(w.Dir)
		_ = os.Remove(caseDir) // gagal = masih ada isi; bukan error
		return nil
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return fmt.Errorf("jobs: hapus %s: %w", d, err)
		}
	}
	return nil
}

// ------------------------------------------------------------ Abort marker

// MarkAborted menulis marker jobs/<caseID>/ABORTED — kill switch §10.
// Task baru untuk case ini akan ditolak selama marker ada.
func MarkAborted(root, caseID string) (string, error) {
	if !ValidID(caseID) {
		return "", fmt.Errorf("jobs: case id %q tidak valid", caseID)
	}
	caseDir := filepath.Join(filepath.Clean(root), caseID)
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		return "", fmt.Errorf("jobs: buat %s: %w", caseDir, err)
	}
	marker := filepath.Join(caseDir, AbortedFile)
	content := fmt.Sprintf("case %s aborted at %s (UTC)\n", caseID, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(marker, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("jobs: tulis %s: %w", marker, err)
	}
	return marker, nil
}

// IsAborted melaporkan apakah case sudah di-abort (task baru ditolak).
func IsAborted(root, caseID string) bool {
	if !ValidID(caseID) {
		return false
	}
	_, err := os.Stat(filepath.Join(filepath.Clean(root), caseID, AbortedFile))
	return err == nil
}
