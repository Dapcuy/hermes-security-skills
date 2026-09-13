package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fullSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "Orders API", "version": "1.2.0"},
  "paths": {
    "/orders": {"get": {"responses": {"200": {"description": "ok"}}}},
    "/orders/{id}": {"get": {"responses": {"200": {"description": "ok"}}}},
    "/users": {"get": {"responses": {"200": {"description": "ok"}}}}
  }
}`

func specTask(t *testing.T, spec string) *Task {
	t.Helper()
	return &Task{TaskID: "oa-1", Input: &Input{Spec: json.RawMessage(spec)}}
}

func TestAnalyzeFullSpec(t *testing.T) {
	var spec map[string]any
	if err := json.Unmarshal([]byte(fullSpec), &spec); err != nil {
		t.Fatalf("test bug: %v", err)
	}
	summary, obs := Analyze(spec)
	if len(obs) != 0 {
		t.Errorf("spec lengkap harus tanpa observation: %#v", obs)
	}
	if summary.Title != "Orders API" || summary.Version != "1.2.0" || summary.PathCount != 3 {
		t.Errorf("summary salah: %+v", summary)
	}
}

func TestAnalyzeMissingFields(t *testing.T) {
	// Setiap kasus pakai map baru — json.Unmarshal ke map lama akan
	// menggabungkan key, bukan menimpa.
	unmarshal := func(doc string) map[string]any {
		t.Helper()
		var s map[string]any
		if err := json.Unmarshal([]byte(doc), &s); err != nil {
			t.Fatalf("test bug: %v", err)
		}
		return s
	}

	// Tanpa info sama sekali.
	_, obs := Analyze(unmarshal(`{"paths":{"/a":{}}}`))
	if len(obs) != 1 || obs[0].Type != "missing_field" || !containsStr(obs[0].Detail, "info") {
		t.Errorf("info hilang harus dilaporkan: %#v", obs)
	}

	// info ada, title kosong.
	_, obs = Analyze(unmarshal(`{"info":{"title":"","version":"1.0"},"paths":{"/a":{}}}`))
	if len(obs) != 1 || !containsStr(obs[0].Detail, "info.title") {
		t.Errorf("title kosong harus dilaporkan: %#v", obs)
	}

	// version hilang.
	_, obs = Analyze(unmarshal(`{"info":{"title":"X"},"paths":{"/a":{}}}`))
	if len(obs) != 1 || !containsStr(obs[0].Detail, "info.version") {
		t.Errorf("version hilang harus dilaporkan: %#v", obs)
	}

	// paths hilang.
	_, obs = Analyze(unmarshal(`{"info":{"title":"X","version":"1"}}`))
	if len(obs) != 1 || !containsStr(obs[0].Detail, "paths") {
		t.Errorf("paths hilang harus dilaporkan: %#v", obs)
	}

	// info bukan object — satu observation untuk info, title/version tidak
	// dicek lagi karena tidak bisa diakses.
	_, obs = Analyze(unmarshal(`{"info":"bukan","paths":{"/a":{}}}`))
	if len(obs) != 1 || !containsStr(obs[0].Detail, "info") {
		t.Errorf("info non-object harus dilaporkan: %#v", obs)
	}
}

func TestExecuteFailClosed(t *testing.T) {
	if _, err := Execute(nil); err == nil {
		t.Error("task nil harus error")
	}
	if _, err := Execute(&Task{TaskID: "x"}); err == nil {
		t.Error("tanpa input harus error")
	}
	bad := Task{TaskID: "x", Input: &Input{Spec: json.RawMessage("[1,2,3]")}}
	if _, err := Execute(&bad); err == nil {
		t.Error("spec array harus ditolak (harus object)")
	}
}

func TestExecuteOutput(t *testing.T) {
	out, err := Execute(specTask(t, fullSpec))
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if out.Result.Status != "observed" {
		t.Errorf("status = %s, mau observed", out.Result.Status)
	}
	if out.Validator.ID != "openapi-analysis" {
		t.Errorf("validator id = %s", out.Validator.ID)
	}
	if out.SpecSummary.PathCount != 3 {
		t.Errorf("path_count = %d, mau 3", out.SpecSummary.PathCount)
	}
	if out.Evidence == nil || len(out.Evidence) != 0 {
		t.Errorf("evidence harus array kosong: %#v", out.Evidence)
	}
}

func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "task.json")
	out := filepath.Join(dir, "nested", "result.json")
	content := `{"task_id":"oa-1","input":{"spec":{"info":{"title":"T","version":"1"},"paths":{"/a":{}}}}}`
	if err := os.WriteFile(in, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis input: %v", err)
	}
	res, err := Run(in, out)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(res.Observations) != 0 {
		t.Errorf("harus tanpa observation: %#v", res.Observations)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("output tidak ditulis: %v", err)
	}
	var parsed Output
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("output bukan JSON: %v", err)
	}
	if parsed.SpecSummary.Title != "T" || parsed.SpecSummary.PathCount != 1 {
		t.Errorf("summary output salah: %+v", parsed.SpecSummary)
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
	noSpec := filepath.Join(dir, "nospec.json")
	if err := os.WriteFile(noSpec, []byte(`{"task_id":"x"}`), 0o600); err != nil {
		t.Fatalf("tulis: %v", err)
	}
	if _, err := Run(noSpec, filepath.Join(dir, "out.json")); err == nil {
		t.Error("tanpa spec harus error")
	}
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}
