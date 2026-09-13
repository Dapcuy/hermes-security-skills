package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAwaitShutdownEOF: loop serve selesai sendiri (stdin EOF) = alasan
// shutdown "stdin_eof" dan error Serve diteruskan.
func TestAwaitShutdownEOF(t *testing.T) {
	done := make(chan error, 1)
	done <- nil
	reason, serveErr := awaitShutdown(context.Background(), done)
	if reason != shutdownReasonEOF {
		t.Errorf("reason = %q, mau %q", reason, shutdownReasonEOF)
	}
	if serveErr != nil {
		t.Errorf("serveErr = %v, mau nil", serveErr)
	}
}

// TestAwaitShutdownSignal: context cancel (jalur SIGINT/SIGTERM — diuji via
// context cancel langsung agar lintas platform) = alasan "signal".
func TestAwaitShutdownSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1) // sengaja tidak pernah diisi: loop masih jalan
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	reason, serveErr := awaitShutdown(ctx, done)
	if reason != shutdownReasonSignal {
		t.Errorf("reason = %q, mau %q", reason, shutdownReasonSignal)
	}
	if serveErr != nil {
		t.Errorf("serveErr = %v, mau nil saat jalur sinyal", serveErr)
	}
}

// TestServeShutdownAuditEntry: entry audit "shutdown" ditulis utuh (satu
// baris JSONL valid dengan action + reason) — baik jalur EOF maupun sinyal.
func TestServeShutdownAuditEntry(t *testing.T) {
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := writeAudit(auditFile, "serve_started", map[string]any{"mode": "mcp"}); err != nil {
		t.Fatalf("writeAudit serve_started: %v", err)
	}
	for _, reason := range []string{shutdownReasonEOF, shutdownReasonSignal} {
		if err := writeAudit(auditFile, "shutdown", map[string]any{
			"mode":   "mcp",
			"reason": reason,
		}); err != nil {
			t.Fatalf("writeAudit shutdown(%s): %v", reason, err)
		}
	}
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("baca audit: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 3 {
		t.Fatalf("audit punya %d baris, mau 3", len(lines))
	}
	var last struct {
		Action string         `json:"action"`
		Detail map[string]any `json:"detail"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &last); err != nil {
		t.Fatalf("baris terakhir bukan JSON utuh (tidak setengah tertulis): %v", err)
	}
	if last.Action != "shutdown" || last.Detail["reason"] != shutdownReasonSignal {
		t.Errorf("entry terakhir = action=%q detail=%v", last.Action, last.Detail)
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if line := s[start:i]; len(line) > 0 {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	return out
}
