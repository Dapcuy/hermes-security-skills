package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Task input (validation-task.json). Semua payload validator berada DI DALAM
// 'input' (kontrak §17: input adalah object berisi data validator).
type Task struct {
	TaskID string `json:"task_id"`
	Input  *Input `json:"input"`
}

// Input payload validator-http: dua response yang dibandingkan.
type Input struct {
	ResponseA *Response `json:"response_a"`
	ResponseB *Response `json:"response_b"`
}

// Response satu HTTP response terstruktur.
type Response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type ValidatorInfo struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type ResultStatus struct {
	Status string `json:"status"`
}

// Observation satu temuan perbandingan.
type Observation struct {
	Type   string `json:"type"` // status_diff | header_diff | body_diff
	Detail string `json:"detail"`
}

// Output validation-result.json.
type Output struct {
	TaskID       string        `json:"task_id"`
	Validator    ValidatorInfo `json:"validator"`
	Result       ResultStatus  `json:"result"`
	Observations []Observation `json:"observations"`
	Evidence     []any         `json:"evidence"`
}

// Run: baca task -> compare -> tulis result. Fail-closed: input tidak
// valid = error (exit code 1 di main).
func Run(inputPath, outputPath string) (*Output, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("validator-http: baca input %s: %w", inputPath, err)
	}
	var task Task
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("validator-http: parse input %s: %w", inputPath, err)
	}
	out, err := Execute(&task)
	if err != nil {
		return nil, err
	}
	if err := writeJSON(outputPath, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Execute memvalidasi task (fail-closed) lalu membandingkan kedua response.
func Execute(task *Task) (*Output, error) {
	if task == nil {
		return nil, errors.New("validator-http: task nil")
	}
	// Kontrak §17: payload validator berada DI DALAM 'input'.
	if task.Input == nil || task.Input.ResponseA == nil || task.Input.ResponseB == nil {
		return nil, errors.New("validator-http: input.response_a dan input.response_b wajib ada (kontrak §17)")
	}
	if task.Input.ResponseA.Status < 100 || task.Input.ResponseA.Status > 599 {
		return nil, fmt.Errorf("validator-http: input.response_a.status tidak valid: %d", task.Input.ResponseA.Status)
	}
	if task.Input.ResponseB.Status < 100 || task.Input.ResponseB.Status > 599 {
		return nil, fmt.Errorf("validator-http: input.response_b.status tidak valid: %d", task.Input.ResponseB.Status)
	}
	out := &Output{
		TaskID:       task.TaskID,
		Validator:    ValidatorInfo{ID: "http-response-comparison", Version: "0.1.0"},
		Observations: Compare(*task.Input.ResponseA, *task.Input.ResponseB),
		Evidence:     []any{},
	}
	out.Result.Status = "observed"
	return out, nil
}

// Compare membandingkan dua response. Nama header dibandingkan
// case-insensitive (header HTTP tidak case-sensitive).
func Compare(a, b Response) []Observation {
	var obs []Observation
	if a.Status != b.Status {
		obs = append(obs, Observation{
			Type:   "status_diff",
			Detail: fmt.Sprintf("status: %d -> %d", a.Status, b.Status),
		})
	}
	ha, hb := normalizeHeaders(a.Headers), normalizeHeaders(b.Headers)
	keys := sortedUnionKeys(ha, hb)
	for _, k := range keys {
		va, ina := ha[k]
		vb, inb := hb[k]
		switch {
		case ina && !inb:
			obs = append(obs, Observation{
				Type:   "header_diff",
				Detail: fmt.Sprintf("header %s: hanya di response_a (nilai %q)", k, va),
			})
		case !ina && inb:
			obs = append(obs, Observation{
				Type:   "header_diff",
				Detail: fmt.Sprintf("header %s: hanya di response_b (nilai %q)", k, vb),
			})
		case va != vb:
			obs = append(obs, Observation{
				Type:   "header_diff",
				Detail: fmt.Sprintf("header %s: %q -> %q", k, va, vb),
			})
		}
	}
	if a.Body != b.Body {
		obs = append(obs, Observation{
			Type:   "body_diff",
			Detail: fmt.Sprintf("body berbeda: %d byte -> %d byte", len(a.Body), len(b.Body)),
		})
	}
	return obs
}

func normalizeHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = v
	}
	return out
}

func sortedUnionKeys(a, b map[string]string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	keys := make([]string, 0, len(a)+len(b))
	for k := range a {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("validator-http: buat direktori %s: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("validator-http: marshal output: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("validator-http: tulis output %s: %w", path, err)
	}
	return nil
}
