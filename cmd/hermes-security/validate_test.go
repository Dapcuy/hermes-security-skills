package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hermes-security-skills/internal/audit"
)

// ---------------------------------------------------------------- validate

func TestLoadValidationTask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "task.json")
	writeFile(t, path, `{
  "task_id": "val-001",
  "validator": {"id": "http-response-comparison", "version": "0.1.0"},
  "input": {},
  "result": {"status": "observation"},
  "evidence": []
}`)
	task, validatorID, taskID, err := loadValidationTask(path)
	if err != nil {
		t.Fatalf("loadValidationTask error: %v", err)
	}
	if taskID != "val-001" || validatorID != "http-response-comparison" {
		t.Errorf("taskID=%q validatorID=%q", taskID, validatorID)
	}
	if task == nil {
		t.Error("task map tidak boleh nil")
	}
}

func TestLoadValidationTaskFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"bukan json", "bukan json"},
		{"tanpa task_id", `{"validator": {"id": "x"}}`},
		{"task_id kosong", `{"task_id": "", "validator": {"id": "x"}}`},
		{"tanpa validator", `{"task_id": "t"}`},
		{"validator tanpa id", `{"task_id": "t", "validator": {"version": "0.1.0"}}`},
		{"validator bukan object", `{"task_id": "t", "validator": "x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "task.json")
			writeFile(t, path, tc.content)
			if _, _, _, err := loadValidationTask(path); err == nil {
				t.Error("harus error (fail-closed, §17)")
			}
		})
	}
	// File hilang.
	if _, _, _, err := loadValidationTask(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("file hilang harus error")
	}
}

func TestResolveImage(t *testing.T) {
	// Fixture manifest inline (bukan manifest asli repo — test terisolasi).
	manifest := filepath.Join(t.TempDir(), "manifest.yaml")
	writeFile(t, manifest, "images:\n  - name: hermes-validator-http\n    tag: 0.1.0\n    digest: '-'\n")

	ref, err := resolveImage(manifest, "", "http-response-comparison")
	if err != nil {
		t.Fatalf("resolveImage error: %v", err)
	}
	if ref != "hermes-validator-http:0.1.0" {
		t.Errorf("ref = %q", ref)
	}

	// Override dev menang atas manifest (§37 build-from-source).
	ov := filepath.Join(t.TempDir(), "overrides.yaml")
	writeFile(t, ov, "http-response-comparison: hermes/validator-http:dev\n")
	ref, err = resolveImage(manifest, ov, "http-response-comparison")
	if err != nil {
		t.Fatalf("resolveImage override error: %v", err)
	}
	if ref != "hermes/validator-http:dev" {
		t.Errorf("override harus menang, dapat %q", ref)
	}

	// Fail-closed: validator tidak dikenal.
	if _, err := resolveImage(manifest, "", "validator-asing"); err == nil {
		t.Error("validator tidak dikenal harus error")
	}
	// Fail-closed: file override rusak.
	bad := filepath.Join(t.TempDir(), "bad-ov.yaml")
	writeFile(t, bad, "\tx: [")
	if _, err := resolveImage(manifest, bad, "http-response-comparison"); err == nil {
		t.Error("override rusak harus error")
	}
}

func TestContainerName(t *testing.T) {
	n1 := containerName("demo case/1", "val-001")
	n2 := containerName("demo case/1", "val-001")
	if n1 == n2 {
		t.Error("dua panggilan harus menghasilkan suffix berbeda (uniqueness)")
	}
	for _, n := range []string{n1, n2} {
		if !strings.HasPrefix(n, "hermes-val-") {
			t.Errorf("prefix salah: %s", n)
		}
		if strings.ContainsAny(n, " /\\:") {
			t.Errorf("nama mengandung karakter invalid: %s", n)
		}
	}
}

// cmdValidate fail-closed tanpa menyentuh docker: runtime tidak didukung
// dan flag wajib kosong harus error sebelum step lain.
func TestCmdValidateFlagsFailClosed(t *testing.T) {
	if err := cmdValidate([]string{"--runtime", "raw-docker", "--task", "x", "--case", "c"}); err == nil {
		t.Error("runtime selain docker harus error (§5.1)")
	}
	if err := cmdValidate([]string{"--runtime", "docker"}); err == nil {
		t.Error("--task/--case kosong harus error")
	}
	if err := cmdValidate([]string{"--runtime", "docker", "--task", "x"}); err == nil {
		t.Error("--case kosong harus error")
	}
	if err := cmdValidate([]string{"--runtime", "docker", "--case", "c"}); err == nil {
		t.Error("--task kosong harus error")
	}
}

// cmdAbort harus menulis marker + audit walau docker tidak tersedia
// (docker error dilaporkan, marker tetap ditulis), dan --case kosong error.
func TestCmdAbortWritesMarkerAndAudit(t *testing.T) {
	root := t.TempDir()
	auditPath := filepath.Join(root, "audit.jsonl")
	// Docker engine memang tersedia di mesin dev, tapi label case "never-existed-case"
	// tidak punya container — abort tetap sukses dengan 0 container.
	if err := cmdAbort([]string{"--case", "never-existed-case", "--jobs-dir", root, "--audit-file", auditPath}); err != nil {
		t.Fatalf("cmdAbort error: %v", err)
	}
	if !IsAbortedForTest(root, "never-existed-case") {
		t.Error("marker ABORTED harus tertulis")
	}
	if err := audit.Verify(auditPath); err != nil {
		t.Errorf("audit chain rusak: %v", err)
	}
	// --case kosong.
	if err := cmdAbort([]string{"--jobs-dir", root, "--audit-file", auditPath}); err == nil {
		t.Error("--case kosong harus error")
	}
}

// IsAbortedForTest menjembatani package jobs untuk asersi test.
func IsAbortedForTest(root, caseID string) bool {
	_, err := os.Stat(filepath.Join(root, caseID, "ABORTED"))
	return err == nil
}
