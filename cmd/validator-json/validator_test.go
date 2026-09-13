package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustDiff(t *testing.T, a, b string) []Observation {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal([]byte(a), &va); err != nil {
		t.Fatalf("json_a tidak valid (test bug): %v", err)
	}
	if err := json.Unmarshal([]byte(b), &vb); err != nil {
		t.Fatalf("json_b tidak valid (test bug): %v", err)
	}
	return Diff(va, vb)
}

func TestDiffIdentical(t *testing.T) {
	obs := mustDiff(t, `{"a":1,"b":{"c":[1,2]}}`, `{"a":1,"b":{"c":[1,2]}}`)
	if len(obs) != 0 {
		t.Errorf("dokumen sama harus tanpa observation, dapat %#v", obs)
	}
}

func TestDiffValueChange(t *testing.T) {
	obs := mustDiff(t, `{"user":{"name":"andi","age":25}}`, `{"user":{"name":"budi","age":25}}`)
	if len(obs) != 1 {
		t.Fatalf("len(obs) = %d, mau 1: %#v", len(obs), obs)
	}
	if !strings.Contains(obs[0].Detail, `$.user.name`) {
		t.Errorf("path salah: %q", obs[0].Detail)
	}
	if !strings.Contains(obs[0].Detail, "andi") || !strings.Contains(obs[0].Detail, "budi") {
		t.Errorf("detail harus memuat nilai lama/baru: %q", obs[0].Detail)
	}
}

func TestDiffMissingKeys(t *testing.T) {
	obs := mustDiff(t, `{"a":1,"b":2}`, `{"a":1}`)
	if len(obs) != 1 {
		t.Fatalf("len(obs) = %d, mau 1", len(obs))
	}
	if !strings.Contains(obs[0].Detail, "$.b") || !strings.Contains(obs[0].Detail, "json_a") {
		t.Errorf("detail salah: %q", obs[0].Detail)
	}
}

func TestDiffArrayTypeChange(t *testing.T) {
	// Panjang beda.
	obs := mustDiff(t, `{"l":[1,2,3]}`, `{"l":[1,2]}`)
	found := false
	for _, o := range obs {
		if strings.Contains(o.Detail, "panjang array 3 -> 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("harus ada observation panjang array: %#v", obs)
	}
	// Elemen beda.
	obs = mustDiff(t, `{"l":[1,2]}`, `{"l":[1,9]}`)
	if len(obs) != 1 || !strings.Contains(obs[0].Detail, "$.l[1]") {
		t.Errorf("elemen array salah: %#v", obs)
	}
}

func TestDiffTypeChange(t *testing.T) {
	obs := mustDiff(t, `{"v":"1"}`, `{"v":1}`)
	if len(obs) != 1 {
		t.Fatalf("len(obs) = %d, mau 1", len(obs))
	}
	if !strings.Contains(obs[0].Detail, "$.v") {
		t.Errorf("path salah: %q", obs[0].Detail)
	}
}

func TestDiffNullAndRoot(t *testing.T) {
	obs := mustDiff(t, `null`, `{"a":1}`)
	if len(obs) != 1 {
		t.Fatalf("len(obs) = %d, mau 1", len(obs))
	}
	if !strings.Contains(obs[0].Detail, "$") {
		t.Errorf("root path salah: %q", obs[0].Detail)
	}
}

func TestExecuteFailClosed(t *testing.T) {
	if _, err := Execute(nil); err == nil {
		t.Error("task nil harus error")
	}
	if _, err := Execute(&Task{TaskID: "t"}); err == nil {
		t.Error("tanpa json_a/json_b harus error")
	}
	bad := Task{TaskID: "t", JsonA: json.RawMessage("{bukan"), JsonB: json.RawMessage("null")}
	if _, err := Execute(&bad); err == nil {
		t.Error("json_a rusak harus error")
	}
}

func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "task.json")
	out := filepath.Join(dir, "result.json")
	content := `{"task_id":"jd-1","json_a":{"x":1},"json_b":{"x":2}}`
	if err := os.WriteFile(in, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis input: %v", err)
	}
	res, err := Run(in, out)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Result.Status != "observed" || len(res.Observations) != 1 {
		t.Errorf("hasil salah: %#v", res)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("output tidak ditulis: %v", err)
	}
	var parsed Output
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("output bukan JSON: %v", err)
	}
	if parsed.Validator.ID != "json-diff" {
		t.Errorf("validator id = %s", parsed.Validator.ID)
	}
}

func TestRunFailClosed(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(in, []byte("bukan json"), 0o600); err != nil {
		t.Fatalf("tulis: %v", err)
	}
	if _, err := Run(in, filepath.Join(dir, "out.json")); err == nil {
		t.Error("input rusak harus error")
	}
	// Tanpa json_b.
	missing := filepath.Join(dir, "missing.json")
	if err := os.WriteFile(missing, []byte(`{"task_id":"x","json_a":{}}`), 0o600); err != nil {
		t.Fatalf("tulis: %v", err)
	}
	if _, err := Run(missing, filepath.Join(dir, "out.json")); err == nil {
		t.Error("tanpa json_b harus error")
	}
}
