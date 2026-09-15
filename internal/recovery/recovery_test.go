package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hermes-security-skills/internal/audit"
)

func TestBackupVerifyRestoreAndTamper(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "audit.jsonl")
	w, err := audit.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append("test", "backup", nil); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.tgz")
	if err := Create(archive, []Source{{Name: "audit.jsonl", Path: src}}); err != nil {
		t.Fatal(err)
	}
	archiveSHA, err := ArchiveSHA256(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigest(archive, archiveSHA); err != nil {
		t.Fatal(err)
	}
	if err := Verify(archive); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "restore")
	if err := Restore(archive, dst); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dst, "audit.jsonl"))
	if !strings.Contains(string(b), `"action":"backup"`) {
		t.Fatalf("restore=%q", b)
	}
	// Any byte change in the archive must fail verification.
	raw, _ := os.ReadFile(archive)
	raw[len(raw)/2] ^= 1
	bad := filepath.Join(root, "bad.tgz")
	os.WriteFile(bad, raw, 0600)
	if err := Verify(bad); err == nil {
		t.Fatal("tampered backup must fail")
	}
}

func TestRejectsTrailingBytesAndOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.WriteFile(filepath.Join(root, "payload"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Create(src, []Source{{Name: "payload", Path: filepath.Join(root, "payload")}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("TRAILING-BYTES")...)
	trailing := filepath.Join(root, "trailing.tgz")
	if err := os.WriteFile(trailing, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(trailing); err == nil {
		t.Fatal("trailing bytes must fail closed")
	}

	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectSources(map[string]string{"jobs": root, "evidence": nested}); err == nil {
		t.Fatal("overlapping backup roots must fail closed")
	}
}

func TestCleanupCaseFailClosed(t *testing.T) {
	root := t.TempDir()
	caseDir := filepath.Join(root, "case")
	os.MkdirAll(filepath.Join(caseDir, "task"), 0700)
	if err := CleanupCase(caseDir, RetentionPolicy{MinAge: time.Hour, AllowedNames: []string{"task"}}, time.Now()); err == nil {
		t.Fatal("young case must fail")
	}
	os.Chtimes(caseDir, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))
	if err := CleanupCase(caseDir, RetentionPolicy{MinAge: time.Hour, AllowedNames: []string{"task"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(caseDir, "task")); !os.IsNotExist(err) {
		t.Fatal("task should be removed")
	}
	os.Mkdir(filepath.Join(caseDir, "evidence"), 0700)
	if err := CleanupCase(caseDir, RetentionPolicy{MinAge: 0, AllowedNames: []string{"task"}}, time.Now()); err == nil || !strings.Contains(err.Error(), "unallowlisted") {
		t.Fatal("unsafe entry must fail closed")
	}
}
