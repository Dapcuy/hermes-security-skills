package proxycore

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hermes-security-skills/internal/scope"
)

// maxRedirectHops: batas keras jumlah redirect yang boleh diikuti walau
// bundle follow_redirects=true (anti infinite loop; fail-closed).
const maxRedirectHops = 10

// maxStoreBodyBytes: batas keras ukuran response body yang dibaca ke memori
// (proteksi DoS ukuran; berlaku untuk evidence maupun passthrough MITM).
const maxStoreBodyBytes = 8 << 20

// Request adalah payload POST /execute {url, method, headers, body, case}.
type Request struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	// Case opsional: label engagement untuk evidence + event index
	// (field case_id). Slug [a-z0-9-], maks 64 — divalidasi fail-closed.
	Case string `json:"case,omitempty"`
}

// Response adalah response target yang dikembalikan ke pemanggil API.
// Body inline di-truncate ke context budget (max_body_bytes) dan selalu
// berupa representasi yang SUDAH diredaksi header-nya (§24/§25).
type Response struct {
	Status    int         `json:"status"`
	Headers   http.Header `json:"headers"`
	Body      string      `json:"body"`
	Truncated bool        `json:"truncated"`
}

// RedirectInfo merekam hasil penanganan redirect (§11: default NO-FOLLOW;
// bila follow_redirects=true tiap hop di-re-validate terhadap scope).
type RedirectInfo struct {
	Followed bool   `json:"followed"`           // minimal satu redirect benar-benar diikuti
	Blocked  bool   `json:"blocked"`            // redirect berhenti karena policy
	Location string `json:"location,omitempty"` // Location terakhir yang terdeteksi
	Hops     int    `json:"hops"`               // jumlah redirect yang diikuti
	Reason   string `json:"reason,omitempty"`   // out_of_scope | budget_habis | rate_limit | max_hops
}

// HopSummary adalah ringkasan satu hop outbound untuk evidence.
type HopSummary struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Status int    `json:"status"`
}

// Result adalah hasil eksekusi satu permintaan /execute (atau satu request
// hasil intercept MITM).
type Result struct {
	Response       Response
	RawHeaders     http.Header // header ASLI (belum diredaksi) — HANYA untuk passthrough TLS MITM; jangan pernah diserialisasi ke API/evidence
	FullBody       []byte      // body penuh (untuk evidence base64 dan passthrough MITM)
	EvidenceRef    string
	EvidenceSHA256 string
	LatencyMS      int64
	Redirect       RedirectInfo
}

// Denial adalah penolakan policy fail-closed (§11): scope -> 403,
// rate limit / budget -> 429.
type Denial struct {
	HTTP   int
	Reason string
}

// Engine menjalankan replay HTTP dengan policy in-line (§11): scope check,
// rate limit, dan budget dievaluasi SAAT eksekusi untuk setiap hop.
type Engine struct {
	bundle   *Bundle
	scope    ScopeChecker
	budget   *Budget
	limiter  *TokenBucket
	evidence *EvidenceStore
	maxBody  int
	client   *http.Client
}

// Options mengonfigurasi Engine (semua opsional).
type Options struct {
	EvidenceDir  string         // default "jobs/evidence"
	MaxBodyBytes int            // 0 = otomatis: min(bundle.max_body_bytes atau 8192, nilai flag bila > 0)
	TLSRootCAs   *x509.CertPool // untuk verifikasi TLS target (testing/lab); nil = system roots
	Scope        ScopeChecker   // override scope checker (testing); default scope.Checker dari bundle
}

// NewEngine membangun Engine dari bundle yang sudah terverifikasi hash-nya.
func NewEngine(b *Bundle, opts Options) (*Engine, error) {
	if b == nil {
		return nil, errors.New("proxycore: bundle nil — fail-closed (semua operasi ditolak)")
	}
	checker := opts.Scope
	if checker == nil {
		sc, err := scope.NewChecker(b.AllowedHosts)
		if err != nil {
			return nil, fmt.Errorf("proxycore: allowlist bundle tidak valid: %w", err)
		}
		checker = sc
	}
	ev, err := NewEvidenceStore(opts.EvidenceDir)
	if err != nil {
		return nil, err
	}
	// Context budget (§24/§25): ambil nilai terkecil antara flag dan bundle —
	// bundle TIDAK boleh dilampaui, flag hanya boleh memperketat.
	maxBody := b.MaxBodyBytesOrDefault()
	if opts.MaxBodyBytes > 0 && opts.MaxBodyBytes < maxBody {
		maxBody = opts.MaxBodyBytes
	}
	return &Engine{
		bundle:   b,
		scope:    checker,
		budget:   NewBudget(b.MaxRequests),
		limiter:  NewTokenBucket(b.RateLimitRPS),
		evidence: ev,
		maxBody:  maxBody,
		client:   newHTTPClient(b.Timeout(), opts.TLSRootCAs),
	}, nil
}

// newHTTPClient membangun client dengan redirect NO-FOLLOW permanen:
// CheckRedirect selalu mengembalikan ErrUseLastResponse, sehingga keputusan
// follow redirect ada di tangan Engine (re-validate scope per hop, §11).
func newHTTPClient(timeout time.Duration, rootCAs *x509.CertPool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // eksplisit: tidak mengikuti HTTP_PROXY lingkungan (fail-closed)
	if rootCAs != nil {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.RootCAs = rootCAs
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// hop adalah state request pada satu iterasi loop eksekusi/redirect.
type hop struct {
	method  string
	url     *url.URL
	headers http.Header
	body    []byte
}

// hopResponse adalah hasil satu request outbound.
type hopResponse struct {
	status    int
	header    http.Header
	body      []byte
	hardTrunc bool
}

// hopByHopRequestHeaders: header yang tidak boleh dibawa dari instruksi replay
// ke request outbound (Host mengikuti URL, panjang body dihitung ulang, dsb.).
var hopByHopRequestHeaders = map[string]bool{
	"host": true, "connection": true, "proxy-connection": true, "keep-alive": true,
	"transfer-encoding": true, "te": true, "trailer": true, "upgrade": true,
	"content-length": true,
}

// sanitizeHeaders mengonversi map instruksi ke http.Header sambil membuang
// header hop-by-hop agar request outbound bersih.
func sanitizeHeaders(in map[string]string) http.Header {
	h := make(http.Header, len(in))
	for k, v := range in {
		if hopByHopRequestHeaders[strings.ToLower(k)] {
			continue
		}
		h.Set(k, v)
	}
	return h
}

func isRedirectStatus(code int) bool {
	return code == http.StatusMovedPermanently || code == http.StatusFound ||
		code == http.StatusSeeOther || code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
}

// validCaseID memvalidasi field `case` opsional (slug sederhana):
// [a-z0-9-], 1..64 karakter. String kosong berarti tanpa case (opsional).
// Charset ketat = aman dipakai sebagai label evidence/index dan mencegah
// path traversal / injeksi label (fail-closed).
func validCaseID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// Execute menjalankan satu permintaan replay dengan seluruh jalur policy
// in-line (§11): (a) scope check per hop, (b) rate limit token bucket,
// (c) budget max_requests, (d) redirect no-follow default / re-validate bila
// follow, (e) redaksi header sebelum data keluar dari proxy, (f) evidence.
func (e *Engine) Execute(ctx context.Context, req Request) (Result, *Denial, error) {
	start := time.Now()

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		return Result{}, &Denial{HTTP: http.StatusBadRequest, Reason: "method wajib diisi"}, nil
	}
	if !allowedMethods[method] {
		return Result{}, &Denial{HTTP: http.StatusBadRequest, Reason: fmt.Sprintf("method %q tidak diizinkan", method)}, nil
	}
	rawURL := strings.TrimSpace(req.URL)
	if rawURL == "" {
		return Result{}, &Denial{HTTP: http.StatusBadRequest, Reason: "url wajib diisi"}, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Result{}, &Denial{HTTP: http.StatusBadRequest, Reason: "url tidak valid"}, nil
	}

	// Validasi case opsional (fail-closed, sebelum network dan evidence):
	// slug [a-z0-9-] maks 64, TANPA trim — nilai non-kosong apa pun yang
	// bukan slug valid (termasuk whitespace) ditolak bersih sebagai 400,
	// sama seperti header invalid. Kosong = tanpa case (opsional).
	caseID := req.Case
	if caseID != "" && !validCaseID(caseID) {
		return Result{}, &Denial{HTTP: http.StatusBadRequest,
			Reason: fmt.Sprintf("case %q tidak valid (slug [a-z0-9-], maks 64 karakter)", caseID)}, nil
	}

	// Validasi nama/nilai header instruksi (fail-closed, sebelum network dan
	// evidence): nama dengan spasi/tab/newline/colon atau nilai dengan byte
	// kontrol = vektor header smuggling — Go http client akan menolaknya saat
	// dial, jadi tolak eksplisit di sini sebagai denial bersih (400), bukan
	// error setelah budget/rate-limit terpakai.
	for name, val := range req.Headers {
		if !validHeaderFieldName(name) {
			return Result{}, &Denial{HTTP: http.StatusBadRequest,
				Reason: fmt.Sprintf("header name tidak valid (bukan RFC 7230 token): %q", name)}, nil
		}
		if !validHeaderFieldValue(val) {
			return Result{}, &Denial{HTTP: http.StatusBadRequest,
				Reason: fmt.Sprintf("header value tidak valid (byte kontrol): %q", name)}, nil
		}
	}

	cur := hop{method: method, url: u, headers: sanitizeHeaders(req.Headers), body: []byte(req.Body)}

	var (
		hops     []HopSummary
		redirect RedirectInfo
		final    *hopResponse
		executed int // jumlah hop yang benar-benar dikirim
	)

	for hopIdx := 0; ; hopIdx++ {
		// (a) Scope check IN-LINE per hop — TOCTOU guard (§11 prinsip 3):
		// di-evaluasi ulang SAAT eksekusi, bukan hanya saat planning.
		if err := e.scope.Check(cur.url.String()); err != nil {
			if hopIdx == 0 {
				return Result{}, &Denial{HTTP: http.StatusForbidden, Reason: err.Error()}, nil
			}
			// Redirect out-of-scope: berhenti, jangan pernah fetch origin
			// out-of-scope (§11 Hard Requirements).
			redirect.Blocked, redirect.Reason = true, "out_of_scope"
			break
		}
		// (c) Budget global (§8/§22): setiap request outbound mengambil slot.
		if !e.budget.Take() {
			if hopIdx == 0 {
				return Result{}, &Denial{HTTP: http.StatusTooManyRequests,
					Reason: fmt.Sprintf("request budget habis (max_requests=%d)", e.bundle.MaxRequests)}, nil
			}
			redirect.Blocked, redirect.Reason = true, "budget_habis"
			break
		}
		// (b) Rate limit (§22): token bucket tanpa menunggu; gagal = tolak.
		if !e.limiter.Allow() {
			if hopIdx == 0 {
				return Result{}, &Denial{HTTP: http.StatusTooManyRequests,
					Reason: fmt.Sprintf("rate limit terlampaui (rate_limit_rps=%d)", e.bundle.RateLimitRPS)}, nil
			}
			redirect.Blocked, redirect.Reason = true, "rate_limit"
			break
		}

		hr, err := e.roundTrip(ctx, cur)
		if err != nil {
			return Result{}, nil, fmt.Errorf("proxycore: request ke target gagal: %w", err)
		}
		executed++
		if hopIdx > 0 {
			redirect.Followed = true
		}
		hops = append(hops, HopSummary{URL: cur.url.String(), Method: cur.method, Status: hr.status})
		final = hr

		if !isRedirectStatus(hr.status) {
			break
		}
		locURL, lerr := hr.locationFor(cur.url)
		if lerr != nil {
			break // Location tidak valid — perlakukan response terakhir sebagai final
		}
		redirect.Location = locURL.String()
		// Default NO-FOLLOW (§11): catat redirect terdeteksi, jangan diikuti.
		if !e.bundle.FollowRedirects {
			break
		}
		if hopIdx+1 > maxRedirectHops {
			redirect.Blocked, redirect.Reason = true, "max_hops"
			break
		}
		cur = nextHop(cur, hr, locURL)
	}

	redirect.Hops = executed - 1
	if redirect.Hops < 0 {
		redirect.Hops = 0
	}

	// Context budget inline (§24/§25): body di-truncate untuk respons API;
	// body penuh hanya masuk evidence file.
	full := final.body
	truncated := len(full) > e.maxBody
	inline := string(full)
	if truncated {
		inline = string(full[:e.maxBody])
	}

	res := Result{
		Response: Response{
			Status:    final.status,
			Headers:   RedactHeaders(final.header),
			Body:      inline,
			Truncated: truncated,
		},
		RawHeaders: final.header,
		FullBody:   full,
		LatencyMS:  time.Since(start).Milliseconds(),
		Redirect:   redirect,
	}

	// Evidence (§25): satu file per eksekusi; request/response penuh (header
	// diredaksi, body base64) + sha256 + captured_at + provenance + case_id
	// (bila caller menyertakan field `case`).
	rec := EvidenceRecord{
		CaseID: caseID,
		Request: EvidenceRequest{
			Method:       method,
			URL:          rawURL,
			Headers:      RedactHeaders(sanitizeHeaders(req.Headers)),
			BodyBase64:   base64.StdEncoding.EncodeToString([]byte(req.Body)),
			BodyEncoding: "base64",
		},
		Response: EvidenceResponse{
			Status:            final.status,
			Headers:           RedactHeaders(final.header),
			BodyBase64:        base64.StdEncoding.EncodeToString(full),
			BodyEncoding:      "base64",
			BodyHardTruncated: final.hardTrunc,
		},
		Redirect:  redirect,
		Hops:      hops,
		LatencyMS: res.LatencyMS,
	}
	ref, shaHex, err := e.evidence.Write(rec)
	if err != nil {
		// Fail-closed: tanpa evidence, konten target tidak boleh masuk
		// reasoning (§25). Eksekusi sudah terjadi, tapi hasil tidak dikirim.
		return Result{}, nil, fmt.Errorf("proxycore: tulis evidence gagal — hasil diblokir (fail-closed): %w", err)
	}
	res.EvidenceRef = ref
	res.EvidenceSHA256 = shaHex
	return res, nil, nil
}

// EvidenceDir mengembalikan path direktori evidence yang dipakai engine.
func (e *Engine) EvidenceDir() string { return e.evidence.Dir() }

// roundTrip mengirim satu request outbound dan membaca response body
// (dengan batas keras maxStoreBodyBytes).
func (e *Engine) roundTrip(ctx context.Context, h hop) (*hopResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, h.method, h.url.String(), bytes.NewReader(h.body))
	if err != nil {
		return nil, fmt.Errorf("bangun request: %w", err)
	}
	for name, vals := range h.headers {
		for _, v := range vals {
			httpReq.Header.Add(name, v)
		}
	}
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStoreBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("baca response body: %w", err)
	}
	hardTrunc := false
	if len(body) > maxStoreBodyBytes {
		body = body[:maxStoreBodyBytes]
		hardTrunc = true
	}
	return &hopResponse{status: resp.StatusCode, header: resp.Header, body: body, hardTrunc: hardTrunc}, nil
}

// locationFor me-resolve header Location terhadap URL hop saat ini
// (mendukung Location relatif).
func (hr *hopResponse) locationFor(base *url.URL) (*url.URL, error) {
	loc := strings.TrimSpace(hr.header.Get("Location"))
	if loc == "" {
		return nil, errors.New("redirect tanpa header Location")
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("location tidak valid: %w", err)
	}
	return base.ResolveReference(ref), nil
}

// nextHop menyiapkan request redirect berikutnya. Semantik mengikuti praktik
// umum client HTTP: 301/302/303 dengan method non-GET/HEAD dikonversi ke GET
// dan body dibuang; 307/308 mempertahankan method dan body. Bila redirect
// pindah host, header kredensial sensitif dibuang agar tidak bocor ke host lain.
func nextHop(cur hop, hr *hopResponse, loc *url.URL) hop {
	n := hop{method: cur.method, url: loc, headers: cur.headers.Clone(), body: cur.body}
	if loc.Host != cur.url.Host {
		for name := range n.headers {
			if isSensitiveHeader(name) {
				n.headers.Del(name)
			}
		}
	}
	if hr.status == http.StatusSeeOther ||
		((hr.status == http.StatusMovedPermanently || hr.status == http.StatusFound) &&
			cur.method != http.MethodGet && cur.method != http.MethodHead) {
		n.method = http.MethodGet
		n.body = nil
	}
	return n
}
