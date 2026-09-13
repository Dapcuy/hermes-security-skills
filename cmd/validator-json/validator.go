package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

// Task input: input.json_a dan input.json_b adalah dua dokumen JSON apa pun
// (kontrak §17: payload validator berada DI DALAM 'input').
type Task struct {
	TaskID string `json:"task_id"`
	Input  *Input `json:"input"`
}

// Input payload validator-json.
type Input struct {
	JsonA json.RawMessage `json:"json_a"`
	JsonB json.RawMessage `json:"json_b"`
}

type ValidatorInfo struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type ResultStatus struct {
	Status string `json:"status"`
}

type Observation struct {
	Type   string `json:"type"` // json_diff
	Detail string `json:"detail"`
}

type Output struct {
	TaskID       string        `json:"task_id"`
	Validator    ValidatorInfo `json:"validator"`
	Result       ResultStatus  `json:"result"`
	Observations []Observation `json:"observations"`
	Evidence     []any         `json:"evidence"`
}

// Run: baca task -> diff -> tulis result. Fail-closed: input tidak
// valid = error.
func Run(inputPath, outputPath string) (*Output, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("validator-json: baca input %s: %w", inputPath, err)
	}
	var task Task
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("validator-json: parse input %s: %w", inputPath, err)
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

// Execute memvalidasi task dan membandingkan kedua dokumen JSON.
func Execute(task *Task) (*Output, error) {
	if task == nil {
		return nil, errors.New("validator-json: task nil")
	}
	// Kontrak §17: payload validator berada DI DALAM 'input'.
	if task.Input == nil || len(task.Input.JsonA) == 0 || len(task.Input.JsonB) == 0 {
		return nil, errors.New("validator-json: input.json_a dan input.json_b wajib ada (kontrak §17)")
	}
	var a, b any
	if err := json.Unmarshal(task.Input.JsonA, &a); err != nil {
		return nil, fmt.Errorf("validator-json: input.json_a tidak valid: %w", err)
	}
	if err := json.Unmarshal(task.Input.JsonB, &b); err != nil {
		return nil, fmt.Errorf("validator-json: input.json_b tidak valid: %w", err)
	}
	out := &Output{
		TaskID:       task.TaskID,
		Validator:    ValidatorInfo{ID: "json-diff", Version: "0.1.0"},
		Observations: Diff(a, b),
		Evidence:     []any{},
	}
	out.Result.Status = "observed"
	return out, nil
}

// Diff membandingkan dua nilai JSON apa pun dengan flatten key-path.
// Root dilambangkan "$"; array ditandai "$[i]".
func Diff(a, b any) []Observation {
	var obs []Observation
	diffJSON("$", a, b, &obs)
	return obs
}

func diffJSON(path string, a, b any, obs *[]Observation) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		for _, k := range sortedStringKeys(am, bm) {
			kp := path + "." + k
			va, ina := am[k]
			vb, inb := bm[k]
			switch {
			case ina && !inb:
				addObs(obs, kp+": hanya di json_a ("+formatVal(va)+")")
			case !ina && inb:
				addObs(obs, kp+": hanya di json_b ("+formatVal(vb)+")")
			default:
				diffJSON(kp, va, vb, obs)
			}
		}
		return
	}
	aa, aarr := a.([]any)
	ba, barr := b.([]any)
	if aarr && barr {
		if len(aa) != len(ba) {
			addObs(obs, fmt.Sprintf("%s: panjang array %d -> %d", path, len(aa), len(ba)))
		}
		n := len(aa)
		if len(ba) < n {
			n = len(ba)
		}
		for i := 0; i < n; i++ {
			diffJSON(fmt.Sprintf("%s[%d]", path, i), aa[i], ba[i], obs)
		}
		return
	}
	if !reflect.DeepEqual(a, b) {
		addObs(obs, path+": "+formatVal(a)+" -> "+formatVal(b))
	}
}

func addObs(obs *[]Observation, detail string) {
	*obs = append(*obs, Observation{Type: "json_diff", Detail: detail})
}

func sortedStringKeys(a, b map[string]any) []string {
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

func formatVal(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("validator-json: buat direktori %s: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("validator-json: marshal output: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("validator-json: tulis output %s: %w", path, err)
	}
	return nil
}
