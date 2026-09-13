package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Task input: input.spec berisi dokumen OpenAPI (JSON) — kontrak §17:
// payload validator berada DI DALAM 'input'.
type Task struct {
	TaskID string `json:"task_id"`
	Input  *Input `json:"input"`
}

// Input payload validator-openapi.
type Input struct {
	Spec json.RawMessage `json:"spec"`
}

type ValidatorInfo struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type ResultStatus struct {
	Status string `json:"status"`
}

type Observation struct {
	Type   string `json:"type"` // missing_field
	Detail string `json:"detail"`
}

// SpecSummary ringkasan spec yang berhasil dibaca.
type SpecSummary struct {
	Title     string `json:"title"`
	Version   string `json:"version"`
	PathCount int    `json:"path_count"`
}

type Output struct {
	TaskID       string        `json:"task_id"`
	Validator    ValidatorInfo `json:"validator"`
	Result       ResultStatus  `json:"result"`
	SpecSummary  SpecSummary   `json:"spec_summary"`
	Observations []Observation `json:"observations"`
	Evidence     []any         `json:"evidence"`
}

// Run: baca task -> analisis spec -> tulis result. Fail-closed: input
// tidak valid = error.
func Run(inputPath, outputPath string) (*Output, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("validator-openapi: baca input %s: %w", inputPath, err)
	}
	var task Task
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("validator-openapi: parse input %s: %w", inputPath, err)
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

// Execute memvalidasi task dan menganalisis spec.
func Execute(task *Task) (*Output, error) {
	if task == nil {
		return nil, errors.New("validator-openapi: task nil")
	}
	// Kontrak §17: payload validator berada DI DALAM 'input'.
	if task.Input == nil || len(task.Input.Spec) == 0 {
		return nil, errors.New("validator-openapi: field 'input.spec' wajib ada (kontrak §17)")
	}
	var spec map[string]any
	if err := json.Unmarshal(task.Input.Spec, &spec); err != nil {
		return nil, fmt.Errorf("validator-openapi: input.spec bukan JSON object: %w", err)
	}
	summary, obs := Analyze(spec)
	out := &Output{
		TaskID:       task.TaskID,
		Validator:    ValidatorInfo{ID: "openapi-analysis", Version: "0.1.0"},
		SpecSummary:  summary,
		Observations: obs,
		Evidence:     []any{},
	}
	out.Result.Status = "observed"
	return out, nil
}

// Analyze memeriksa fields wajib spec: info.title, info.version, dan paths.
// Field hilang = observation (bukan error), sesuai kontrak "report missing".
func Analyze(spec map[string]any) (SpecSummary, []Observation) {
	var obs []Observation
	summary := SpecSummary{}

	info, ok := spec["info"].(map[string]any)
	if !ok {
		obs = append(obs, Observation{Type: "missing_field", Detail: "info wajib ada (object)"})
	} else {
		title, ok := info["title"].(string)
		if !ok || strings.TrimSpace(title) == "" {
			obs = append(obs, Observation{Type: "missing_field", Detail: "info.title wajib ada (string tidak kosong)"})
		} else {
			summary.Title = title
		}
		version, ok := info["version"].(string)
		if !ok || strings.TrimSpace(version) == "" {
			obs = append(obs, Observation{Type: "missing_field", Detail: "info.version wajib ada (string tidak kosong)"})
		} else {
			summary.Version = version
		}
	}

	paths, ok := spec["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		obs = append(obs, Observation{Type: "missing_field", Detail: "paths wajib ada (object tidak kosong)"})
	} else {
		summary.PathCount = len(paths)
	}
	return summary, obs
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("validator-openapi: buat direktori %s: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("validator-openapi: marshal output: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("validator-openapi: tulis output %s: %w", path, err)
	}
	return nil
}
