package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareNoDiff(t *testing.T) {
	a := Response{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: "ok"}
	b := Response{Status: 200, Headers: map[string]string{"content-type": "application/json"}, Body: "ok"}
	obs := Compare(a, b)
	if len(obs) != 0 {
		t.Errorf("response identik harus tanpa observation, dapat %#v", obs)
	}
}

func TestCompareStatusDiff(t *testing.T) {
	obs := Compare(
		Response{Status: 200},
		Response{Status: 404},
	)
	if len(obs) != 1 {
		t.Fatalf("len(obs) = %d, mau 1", len(obs))
	}
	if obs[0].Type != "status_diff" {
		t.Errorf("type = %s, mau status_diff", obs[0].Type)
	}
	want := "status: 200 -> 404"
	if obs[0].Detail != want {
		t.Errorf("detail = %q, mau %q", obs[0].Detail, want)
	}
}

func TestCompareHeaderDiff(t *testing.T) {
	a := Response{Status: 200, Headers: map[string]string{
		"X-Only-A":  "1",
		"X-Changed": "old",
		"Same":      "s",
	}}
	b := Response{Status: 200, Headers: map[string]string{
		"x-only-b":  "2",
		"x-changed": "new",
		"same":      "s",
	}}
	obs := Compare(a, b)
	if len(obs) != 3 {
		t.Fatalf("len(obs) = %d, mau 3: %#v", len(obs), obs)
	}
	for _, o := range obs {
		if o.Type != "header_diff" {
			t.Errorf("type = %s, mau header_diff", o.Type)
		}
	}
	joined := obs[0].Detail + "|" + obs[1].Detail + "|" + obs[2].Detail
	for _, want := range []string{"x-only-a", "x-only-b", "x-changed"} {
		if !contains(joined, want) {
			t.Errorf("detail harus menyebut %s: %q", want, joined)
		}
	}
}

func TestCompareBodyDiff(t *testing.T) {
	obs := Compare(
		Response{Status: 200, Body: "aaa"},
		Response{Status: 200, Body: "bbbb"},
	)
	if len(obs) != 1 || obs[0].Type != "body_diff" {
		t.Fatalf("harus tepat satu body_diff: %#v", obs)
	}
	if !contains(obs[0].Detail, "3 byte -> 4 byte") {
		t.Errorf("detail = %q", obs[0].Detail)
	}
}

func TestExecuteFailClosed(t *testing.T) {
	if _, err := Execute(nil); err == nil {
		t.Error("task nil harus error")
	}
	if _, err := Execute(&Task{TaskID: "t"}); err == nil {
		t.Error("tanpa response_a/response_b harus error")
	}
	bad := Task{TaskID: "t", ResponseA: &Response{Status: 42}, ResponseB: &Response{Status: 200}}
	if _, err := Execute(&bad); err == nil {
		t.Error("status di luar 100-599 harus error")
	}
}

func TestExecuteOutputShape(t *testing.T) {
	task := Task{
		TaskID:    "val-001",
		ResponseA: &Response{Status: 200, Body: "a"},
		ResponseB: &Response{Status: 200, Body: "b"},
	}
	out, err := Execute(&task)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if out.Result.Status != "observed" {
		t.Errorf("status = %s, mau observed", out.Result.Status)
	}
	if out.Validator.ID != "http-response-comparison" {
		t.Errorf("validator id = %s", out.Validator.ID)
	}
	if out.Evidence == nil || len(out.Evidence) != 0 {
		t.Errorf("evidence harus array kosong: %#v", out.Evidence)
	}
	if len(out.Observations) != 1 || out.Observations[0].Type != "body_diff" {
		t.Errorf("observations salah: %#v", out.Observations)
	}
}

func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "validation-task.json")
	out := filepath.Join(dir, "nested", "validation-result.json")
	task := map[string]any{
		"task_id":    "val-001",
		"response_a": map[string]any{"status": 200, "headers": map[string]string{"Server": "a"}, "body": "same"},
		"response_b": map[string]any{"status": 200, "headers": map[string]string{"Server": "b"}, "body": "same"},
	}
	data, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatalf("tulis input: %v", err)
	}

	res, err := Run(in, out)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.TaskID != "val-001" {
		t.Errorf("task_id = %s", res.TaskID)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("output tidak ditulis: %v", err)
	}
	var parsed Output
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("output bukan JSON valid: %v", err)
	}
	if parsed.Result.Status != "observed" || len(parsed.Observations) != 1 {
		t.Errorf("output salah: %#v", parsed)
	}
}

func TestRunFailClosed(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(in, []byte("{bukan json"), 0o600); err != nil {
		t.Fatalf("tulis: %v", err)
	}
	if _, err := Run(in, filepath.Join(dir, "out.json")); err == nil {
		t.Error("input JSON rusak harus error")
	}
	if _, err := Run(filepath.Join(dir, "missing.json"), filepath.Join(dir, "out.json")); err == nil {
		t.Error("input hilang harus error")
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
