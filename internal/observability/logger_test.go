package observability

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLoggerEmitsJSONLWithoutSensitiveRequestFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)
	if err := logger.Event("info", "request_completed", map[string]any{
		"request_id": "req-1", "status": 200, "latency_ms": 12, "outcome": "executed",
	}); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["event"] != "request_completed" || record["request_id"] != "req-1" {
		t.Fatalf("unexpected record: %#v", record)
	}
	if strings.Contains(buf.String(), "url") || strings.Contains(buf.String(), "target") || strings.Contains(buf.String(), "body") {
		t.Fatalf("sensitive fields leaked: %s", buf.String())
	}
	if err := logger.Event("info", "nested", map[string]any{"details": map[string]any{"url": "https://example.invalid"}}); err == nil {
		t.Fatal("sensitive nested value must be rejected")
	}
}
