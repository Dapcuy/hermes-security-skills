package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"hermes-security-skills/internal/observability"
	"hermes-security-skills/internal/proxycore"
)

// Server adalah control channel HTTP hermes-proxy (§11). Seluruh logika
// policy ada di Engine (internal/proxycore) yang dipakai bersama Mode 1
// dan Mode 2 (MITM) — satu jalur policy, dua pintu masuk.
type Server struct {
	engine  *proxycore.Engine
	metrics *observability.Metrics
	logger  *observability.Logger
	seq     atomic.Uint64
}

// HandleExecute melayani POST /execute {url, method, headers, body}.
// Semua header sensitif sudah diredaksi dan body ter-truncate ke context
// budget sebelum respons keluar dari proxy (§24/§25).
func (s *Server) HandleExecute(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := fmt.Sprintf("req-%d", s.seq.Add(1))
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	outcome := "unknown"
	defer func() {
		ms := uint64(time.Since(start).Milliseconds())
		if s.metrics != nil {
			s.metrics.ObserveLatency(ms)
		}
		if s.logger != nil {
			_ = s.logger.Event("info", "request_completed", map[string]any{
				"request_id": requestID,
				"method":     r.Method,
				"status":     sw.status,
				"latency_ms": ms,
				"outcome":    outcome,
			})
		}
	}()
	if s.metrics != nil {
		s.metrics.Requests.Add(1)
	}
	if s.engine == nil {
		outcome = "denied"
		if s.metrics != nil {
			s.metrics.Denied.Add(1)
		}
		deny(sw, http.StatusForbidden, "engine tidak tersedia — semua operasi ditolak (fail-closed)")
		return
	}
	if r.Method != http.MethodPost {
		outcome = "denied"
		if s.metrics != nil {
			s.metrics.Denied.Add(1)
		}
		deny(sw, http.StatusMethodNotAllowed, "hanya POST /execute")
		return
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req proxycore.Request
	if err := dec.Decode(&req); err != nil {
		outcome = "denied"
		if s.metrics != nil {
			s.metrics.Denied.Add(1)
		}
		deny(sw, http.StatusBadRequest, "body JSON tidak valid")
		return
	}

	res, denial, err := s.engine.Execute(r.Context(), req)
	if denial != nil {
		outcome = "denied"
		if s.metrics != nil {
			s.metrics.Denied.Add(1)
		}
		deny(sw, denial.HTTP, denial.Reason)
		return
	}
	if err != nil {
		outcome = "error"
		if s.metrics != nil {
			s.metrics.Errors.Add(1)
		}
		respond(sw, http.StatusBadGateway, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	outcome = "executed"
	if s.metrics != nil {
		s.metrics.Executed.Add(1)
	}
	respond(sw, http.StatusOK, map[string]any{
		"status":          "executed",
		"response":        res.Response,
		"evidence_ref":    res.EvidenceRef,
		"evidence_sha256": res.EvidenceSHA256,
		"latency_ms":      res.LatencyMS,
		"redirect":        res.Redirect,
	})
}

// HandleHealth is a side-effect-free liveness probe. It never contacts a target.
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// HandleReady is a local readiness probe. A loaded engine implies that the
// policy bundle was verified and the evidence store was initialized.
func (s *Server) HandleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.engine == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func deny(w http.ResponseWriter, code int, reason string) {
	respond(w, code, map[string]any{"status": "denied", "reason": reason})
}

func respond(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
