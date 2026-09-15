package observability

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Metrics is a bounded, process-local Prometheus collector. It deliberately
// exposes no target, path, case, evidence, or credential labels.
type Metrics struct {
	Requests atomic.Uint64
	Executed atomic.Uint64
	Denied   atomic.Uint64
	Errors   atomic.Uint64

	LatencyCount atomic.Uint64
	LatencySumMS atomic.Uint64
	LatencyLE    [7]atomic.Uint64 // <= 10, 50, 100, 500, 1000, 5000, +Inf
}

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) ObserveLatency(ms uint64) {
	m.LatencyCount.Add(1)
	m.LatencySumMS.Add(ms)
	limits := [...]uint64{10, 50, 100, 500, 1000, 5000}
	for i, limit := range limits {
		if ms <= limit {
			m.LatencyLE[i].Add(1)
		}
	}
	m.LatencyLE[6].Add(1)
}

func (m *Metrics) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP hermes_proxy_requests_total HTTP requests received by the proxy.\n# TYPE hermes_proxy_requests_total counter\nhermes_proxy_requests_total %d\n", m.Requests.Load())
	fmt.Fprintf(w, "# HELP hermes_proxy_executions_total Executions that passed policy.\n# TYPE hermes_proxy_executions_total counter\nhermes_proxy_executions_total %d\n", m.Executed.Load())
	fmt.Fprintf(w, "# HELP hermes_proxy_denials_total Requests denied by policy or validation.\n# TYPE hermes_proxy_denials_total counter\nhermes_proxy_denials_total %d\n", m.Denied.Load())
	fmt.Fprintf(w, "# HELP hermes_proxy_errors_total Execution errors.\n# TYPE hermes_proxy_errors_total counter\nhermes_proxy_errors_total %d\n", m.Errors.Load())
	fmt.Fprintf(w, "# HELP hermes_proxy_request_duration_ms Request latency in milliseconds.\n# TYPE hermes_proxy_request_duration_ms histogram\n")
	limits := [...]string{"10", "50", "100", "500", "1000", "5000"}
	for i, limit := range limits {
		fmt.Fprintf(w, "hermes_proxy_request_duration_ms_bucket{le=\"%s\"} %d\n", limit, m.LatencyLE[i].Load())
	}
	fmt.Fprintf(w, "hermes_proxy_request_duration_ms_bucket{le=\"+Inf\"} %d\nhermes_proxy_request_duration_ms_sum %d\nhermes_proxy_request_duration_ms_count %d\n", m.LatencyLE[6].Load(), m.LatencySumMS.Load(), m.LatencyCount.Load())
}
