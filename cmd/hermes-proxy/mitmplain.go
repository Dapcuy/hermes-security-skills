package main

// mitmplain.go — wrapper handler untuk listener MITM (Mode 2).
//
// Kontrak HTTP proxy (RFC 9112 §3.2.2): client yang dikonfigurasi memakai
// proxy HTTP untuk target http:// TIDAK mengirim CONNECT, melainkan request
// absolute-form langsung ke proxy, mis. "GET http://localhost:8000/ HTTP/1.1".
// CONNECT hanya dipakai untuk tunneling https. Browser asli (Chrome/Edge)
// mengikuti kontrak ini, jadi listener MITM wajib melayani keduanya:
//
//	CONNECT host:port     -> TLS interception (proxycore.NewMITMProxy)
//	GET http://host/path  -> absolute-form plaintext (handler ini)
//
// Kedua jalur melewati Engine yang SAMA dengan Mode 1 — scope, budget,
// rate limit, redaksi, dan evidence identik (fail-closed tetap berlaku:
// host di luar allowlist = 403 tanpa menyentuh target).

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"hermes-security-skills/internal/proxycore"
)

// maxProxyRequestBody: batas keras baca body request client pada jalur
// absolute-form (selaras maxStoreBodyBytes di proxycore — proteksi DoS ukuran).
const maxProxyRequestBody = 8 << 20

// mitmPlainHandler membungkus handler CONNECT MITM dengan dukungan
// absolute-form plaintext untuk target http://.
type mitmPlainHandler struct {
	connect http.Handler      // CONNECT tunneling + TLS interception
	engine  *proxycore.Engine // jalur policy tunggal (Mode 1 == Mode 2)
}

// ServeHTTP memilah: CONNECT / origin-form -> handler CONNECT (yang menolak
// origin-form dengan 405); absolute-form -> eksekusi via Engine.
func (h *mitmPlainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect || r.URL.Host == "" {
		// CONNECT -> tunnel; origin-form di port proxy -> didelegasikan
		// (handler CONNECT membalas "hanya melayani CONNECT").
		h.connect.ServeHTTP(w, r)
		return
	}
	h.serveAbsoluteForm(w, r)
}

// serveAbsoluteForm mengeksekusi request plaintext absolute-form melalui
// jalur policy Engine, lalu menulis kembali response target: header ASLI
// (tanpa hop-by-hop) + body penuh — redaksi hanya berlaku untuk data yang
// masuk evidence/reasoning (§24/§25), bukan pada stream ke client.
func (h *mitmPlainHandler) serveAbsoluteForm(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxProxyRequestBody+1))
		if err == nil && len(b) > maxProxyRequestBody {
			b = b[:maxProxyRequestBody]
		}
		body = b
	}

	headers := make(map[string]string, len(r.Header))
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}

	res, denial, err := h.engine.Execute(r.Context(), proxycore.Request{
		URL:     r.URL.String(), // absolute-form: URL sudah lengkap dengan host
		Method:  r.Method,
		Headers: headers,
		Body:    string(body),
	})
	switch {
	case denial != nil:
		writePlainJSON(w, denial.HTTP, map[string]string{"status": "denied", "reason": denial.Reason})
	case err != nil:
		writePlainJSON(w, http.StatusBadGateway, map[string]string{"status": "error", "error": err.Error()})
	default:
		writeRawToResponseWriter(w, res)
	}
}

// writePlainJSON menulis response JSON minimal untuk denial/error pada jalur
// absolute-form (padanan writeSimpleJSON di mitm.go untuk jalur tunnel).
func writePlainJSON(w http.ResponseWriter, code int, payload map[string]string) {
	b, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

// writeRawToResponseWriter menulis response target ke client jalur
// absolute-form via http.ResponseWriter: status + header asli (tanpa
// hop-by-hop) + Content-Length + body penuh (padanan writeRawResponse di
// mitm.go yang menulis ke net.Conn tunnel).
func writeRawToResponseWriter(w http.ResponseWriter, res proxycore.Result) {
	h := w.Header()
	for name, vals := range res.RawHeaders {
		switch strings.ToLower(name) {
		case "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection":
			continue // hop-by-hop / diatur ulang oleh net/http
		}
		for _, v := range vals {
			h.Add(name, v)
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(res.FullBody)))
	w.WriteHeader(res.Response.Status)
	_, _ = w.Write(res.FullBody)
}
