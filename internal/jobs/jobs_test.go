package jobs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateLayout(t *testing.T) {
	root := t.TempDir()
	ws, err := Create(root, "demo", "val-001")
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	// Struktur §18 lengkap.
	for _, d := range []string{ws.InputDir, ws.OutputDir, ws.ArtifactsDir, ws.LogsDir} {
		info, err := os.Stat(d)
		if err != nil || !info.IsDir() {
			t.Errorf("direktori %s harus ada", d)
		}
	}
	// Relatif terhadap root yang diberikan.
	if !strings.HasPrefix(ws.Dir, filepath.Join(root, "demo", "val-001")) {
		t.Errorf("Dir = %s, harus di bawah %s", ws.Dir, root)
	}
	if ws.TaskPath() != filepath.Join(root, "demo", "val-001", "input", TaskFile) {
		t.Errorf("TaskPath = %s", ws.TaskPath())
	}
	if ws.ResultPath() != filepath.Join(root, "demo", "val-001", "output", ResultFile) {
		t.Errorf("ResultPath = %s", ws.ResultPath())
	}
	// Idempotent: Create ulang tidak error.
	if _, err := Create(root, "demo", "val-001"); err != nil {
		t.Errorf("Create ulang harus idempotent: %v", err)
	}
}

func TestCreateFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		caseID string
		taskID string
	}{
		{"case traversal", "../evil", "t"},
		{"case slash", "a/b", "t"},
		{"case kosong", "", "t"},
		{"case titik dua", "a:b", "t"},
		{"task traversal", "c", "../../evil"},
		{"task kosong", "c", ""},
		{"id terlalu panjang", strings.Repeat("a", 100), "t"},
	}
	root := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Create(root, tc.caseID, tc.taskID); err == nil {
				t.Errorf("Create(%q, %q) harus error (fail-closed)", tc.caseID, tc.taskID)
			}
		})
	}
}

func TestWriteAndCollectRoundtrip(t *testing.T) {
	ws, err := Create(t.TempDir(), "demo", "val-001")
	if err != nil {
		t.Fatal(err)
	}
	task := map[string]any{
		"task_id":   "val-001",
		"validator": map[string]any{"id": "http-response-comparison", "version": "0.1.0"},
		"input":     map[string]any{"target": "authorized-target"},
	}
	if err := ws.WriteTask(task); err != nil {
		t.Fatalf("WriteTask error: %v", err)
	}
	// File task parseable kembali.
	raw, err := os.ReadFile(ws.TaskPath())
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("task tidak parseable: %v", err)
	}

	// Result belum ada = error eksplisit (bukan silent).
	if _, err := ws.CollectResult(); err == nil {
		t.Error("CollectResult sebelum result ada harus error")
	}

	want := map[string]any{
		"task_id": "val-001",
		"result":  map[string]any{"status": "observed"},
	}
	data, _ := json.Marshal(want)
	if err := os.WriteFile(ws.ResultPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ws.CollectResult()
	if err != nil {
		t.Fatalf("CollectResult error: %v", err)
	}
	if got["task_id"] != "val-001" {
		t.Errorf("task_id = %v", got["task_id"])
	}

	// Result korup = error fail-closed.
	if err := os.WriteFile(ws.ResultPath(), []byte("{korup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.CollectResult(); err == nil {
		t.Error("result korup harus error")
	}
}

func TestWriteLog(t *testing.T) {
	ws, err := Create(t.TempDir(), "demo", "val-001")
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteLog("container.log", []byte("stdout container\n")); err != nil {
		t.Fatalf("WriteLog error: %v", err)
	}
	if _, err := os.Stat(ws.ContainerLogPath()); err != nil {
		t.Errorf("log harus ada: %v", err)
	}
}

func TestCleanup(t *testing.T) {
	root := t.TempDir()

	// Tanpa keep-artifacts: seluruh task dir hilang.
	ws, err := Create(root, "case-a", "t1")
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteTask(map[string]any{"x": 1}); err != nil {
		t.Fatal(err)
	}
	if err := ws.Cleanup(false); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}
	if _, err := os.Stat(ws.Dir); !os.IsNotExist(err) {
		t.Errorf("task dir harus terhapus: %v", err)
	}

	// Dengan keep-artifacts: artifacts bertahan, input/output/logs hilang.
	ws2, err := Create(root, "case-a", "t2")
	if err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(ws2.ArtifactsDir, "evidence-1.bin")
	if err := os.WriteFile(art, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ws2.Cleanup(true); err != nil {
		t.Fatalf("Cleanup(keep) error: %v", err)
	}
	if _, err := os.Stat(art); err != nil {
		t.Errorf("artifacts harus bertahan: %v", err)
	}
	for _, d := range []string{ws2.InputDir, ws2.OutputDir, ws2.LogsDir} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("%s harus terhapus (keepArtifacts=true)", d)
		}
	}
}

func TestAbortMarker(t *testing.T) {
	root := t.TempDir()
	if IsAborted(root, "demo") {
		t.Error("case baru belum aborted")
	}
	marker, err := MarkAborted(root, "demo")
	if err != nil {
		t.Fatalf("MarkAborted error: %v", err)
	}
	if !strings.HasSuffix(filepath.ToSlash(marker), "demo/ABORTED") {
		t.Errorf("marker = %s, harus <root>/demo/ABORTED", marker)
	}
	if !IsAborted(root, "demo") {
		t.Error("setelah MarkAborted, IsAborted harus true")
	}
	data, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(data), "demo") {
		t.Errorf("isi marker = %s (%v)", data, err)
	}
	// ID invalid ditolak.
	if _, err := MarkAborted(root, "../evil"); err == nil {
		t.Error("MarkAborted id invalid harus error")
	}
	if IsAborted(root, "../evil") {
		t.Error("IsAborted id invalid harus false")
	}
}
