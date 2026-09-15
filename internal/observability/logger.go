package observability

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

func validateLogValue(v any) error {
	switch value := v.(type) {
	case string:
		lower := strings.ToLower(value)
		for _, marker := range []string{"http://", "https://", "authorization:", "bearer ", "token=", "password=", "secret="} {
			if strings.Contains(lower, marker) {
				return fmt.Errorf("observability: sensitive value rejected")
			}
		}
	case map[string]any:
		for k, child := range value {
			lower := strings.ToLower(k)
			for _, forbidden := range []string{"url", "target", "body", "token", "credential", "secret", "password", "header", "query", "evidence", "case", "approval"} {
				if strings.Contains(lower, forbidden) {
					return fmt.Errorf("observability: sensitive nested field rejected: %s", k)
				}
			}
			if err := validateLogValue(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := validateLogValue(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// Logger emits bounded JSONL operational events. Callers must pass only
// non-sensitive fields; request payloads and target identifiers are excluded
// by the proxy contract.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

func NewLogger(w io.Writer) *Logger { return &Logger{w: w} }

func (l *Logger) Event(level, event string, fields map[string]any) error {
	if l == nil || l.w == nil {
		return nil
	}
	record := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"event": event,
	}
	for k, v := range fields {
		lower := strings.ToLower(k)
		for _, forbidden := range []string{"url", "target", "body", "token", "credential", "secret", "password", "header", "query", "evidence", "case", "approval"} {
			if strings.Contains(lower, forbidden) {
				return fmt.Errorf("observability: sensitive field rejected: %s", k)
			}
		}
		if err := validateLogValue(v); err != nil {
			return err
		}
		record[k] = v
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.w.Write(append(data, '\n'))
	return err
}
