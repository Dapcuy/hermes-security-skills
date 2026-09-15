package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandlerRendersBoundedCounters(t *testing.T) {
	m := NewMetrics()
	m.Requests.Add(3)
	m.Executed.Add(1)
	m.Denied.Add(2)

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler(w, r)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "hermes_proxy_requests_total 3") || !strings.Contains(body, "hermes_proxy_denials_total 2") {
		t.Fatalf("metrics response = (%d, %q)", w.Code, body)
	}
	for _, forbidden := range []string{"url", "case", "evidence", "token", "Authorization"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics contains forbidden label/data %q", forbidden)
		}
	}
}

func TestMetricsHandlerRejectsNonGet(t *testing.T) {
	w := httptest.NewRecorder()
	NewMetrics().Handler(w, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d, want 405", w.Code)
	}
}
