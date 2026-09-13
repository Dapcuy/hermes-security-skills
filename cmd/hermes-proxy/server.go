package main

import (
	"encoding/json"
	"net/http"

	"hermes-security-skills/internal/proxycore"
)

// Server adalah control channel HTTP hermes-proxy (§11). Seluruh logika
// policy ada di Engine (internal/proxycore) yang dipakai bersama Mode 1
// dan Mode 2 (MITM) — satu jalur policy, dua pintu masuk.
type Server struct {
	engine *proxycore.Engine
}

// HandleExecute melayani POST /execute {url, method, headers, body}.
//
// Contract respons:
//
//	200 {"status":"executed", response:{status,headers,body,truncated},
//	     evidence_ref, evidence_sha256, latency_ms, redirect:{...}}
//	403 {"status":"denied","reason":...}   — scope/policy (fail-closed)
//	429 {"status":"denied","reason":...}   — budget habis / rate limit
//	400/405 {"status":"denied","reason":...} — input tidak valid
//	502 {"status":"error","error":...}     — kegagalan transport ke target
//
// Semua header sensitif sudah diredaksi dan body ter-truncate ke context
// budget SEBELUM respons ini keluar dari proxy (§24/§25).
func (s *Server) HandleExecute(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		deny(w, http.StatusForbidden, "engine tidak tersedia — semua operasi ditolak (fail-closed)")
		return
	}
	if r.Method != http.MethodPost {
		deny(w, http.StatusMethodNotAllowed, "hanya POST /execute")
		return
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req proxycore.Request
	if err := dec.Decode(&req); err != nil {
		deny(w, http.StatusBadRequest, "body JSON tidak valid: "+err.Error())
		return
	}

	res, denial, err := s.engine.Execute(r.Context(), req)
	if denial != nil {
		deny(w, denial.HTTP, denial.Reason)
		return
	}
	if err != nil {
		respond(w, http.StatusBadGateway, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	respond(w, http.StatusOK, map[string]any{
		"status":          "executed",
		"response":        res.Response,
		"evidence_ref":    res.EvidenceRef,
		"evidence_sha256": res.EvidenceSHA256,
		"latency_ms":      res.LatencyMS,
		"redirect":        res.Redirect,
	})
}

func deny(w http.ResponseWriter, code int, reason string) {
	respond(w, code, map[string]any{"status": "denied", "reason": reason})
}

func respond(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
