package proxycore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestExecuteHappyPath: eksekusi HTTP nyata ke target lokal (httptest),
// evidence tertulis, body inline utuh (di bawah context budget).
func TestExecuteHappyPath(t *testing.T) {
	finalHit := atomic.Int32{}
	ts, bundle := newLocalTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHit.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "halo dari target lokal")
	}))
	eng := mustEngine(t, bundle)

	res, denial, err := eng.Execute(context.Background(), Request{URL: localURL(ts) + "/halo", Method: "GET"})
	if err != nil || denial != nil {
		t.Fatalf("Execute error=%v denial=%+v", err, denial)
	}
	if res.Response.Status != http.StatusOK {
		t.Errorf("status = %d, mau 200", res.Response.Status)
	}
	if res.Response.Body != "halo dari target lokal" {
		t.Errorf("body = %q", res.Response.Body)
	}
	if res.Response.Truncated {
		t.Error("body pendek tidak boleh truncated")
	}
	if res.Response.Headers.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type = %q", res.Response.Headers.Get("Content-Type"))
	}
	if res.EvidenceRef == "" || res.EvidenceSHA256 == "" {
		t.Error("evidence_ref dan evidence_sha256 wajib terisi")
	}
	if res.LatencyMS < 0 {
		t.Errorf("latency_ms = %d", res.LatencyMS)
	}
	if finalHit.Load() != 1 {
		t.Errorf("target dipanggil %d kali, mau 1", finalHit.Load())
	}
	// Evidence file benar-benar ada.
	if _, err := os.Stat(filepath.Join(eng.EvidenceDir(), res.EvidenceRef)); err != nil {
		t.Errorf("evidence file tidak ada: %v", err)
	}
}

// TestExecuteScopeDenied: host di luar allowlist ditolak 403 dan target
// TIDAK pernah dihubungi (fail-closed).
func TestExecuteScopeDenied(t *testing.T) {
	hit := atomic.Int32{}
	ts, bundle := newLocalTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		fmt.Fprint(w, "tidak boleh tercapai")
	}))
	eng := mustEngine(t, bundle)

	cases := []struct {
		name string
		url  string
	}{
		{"host lain", "http://other.local/"},
		{"ip loopback literal ditolak keras", ts.URL}, // 127.0.0.1 = denied oleh scope
		{"substring host", "http://evil-localhost.local/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, denial, err := eng.Execute(context.Background(), Request{URL: tc.url, Method: "GET"})
			if err != nil {
				t.Fatalf("Execute error: %v", err)
			}
			if denial == nil || denial.HTTP != http.StatusForbidden {
				t.Fatalf("mau denial 403, dapat %+v (res=%+v)", denial, res)
			}
			if denial.Reason == "" {
				t.Error("reason wajib terisi")
			}
		})
	}
	if hit.Load() != 0 {
		t.Errorf("target dipanggil %d kali, mau 0", hit.Load())
	}
	// Denial tidak menghasilkan evidence (tidak ada eksekusi).
	entries, _ := os.ReadDir(eng.EvidenceDir())
	if len(entries) != 0 {
		t.Errorf("denial scope tidak boleh menulis evidence (%d file)", len(entries))
	}
}

// TestExecuteBudgetExhausted: max_requests habis -> 429 fail-closed.
func TestExecuteBudgetExhausted(t *testing.T) {
	ts, bundle := newLocalTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	bundle.MaxRequests = 1
	eng := mustEngine(t, bundle)

	res, denial, err := eng.Execute(context.Background(), Request{URL: localURL(ts) + "/1", Method: "GET"})
	if err != nil || denial != nil {
		t.Fatalf("eksekusi pertama harus sukses: err=%v denial=%+v", err, denial)
	}
	if res.Response.Status != 200 {
		t.Fatalf("status pertama = %d", res.Response.Status)
	}
	_, denial, err = eng.Execute(context.Background(), Request{URL: localURL(ts) + "/2", Method: "GET"})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if denial == nil || denial.HTTP != http.StatusTooManyRequests {
		t.Fatalf("mau denial 429, dapat %+v", denial)
	}
	if denial.Reason == "" {
		t.Error("reason budget wajib terisi")
	}
}

// TestExecuteRateLimitLimited: rate_limit_rps=1 -> request kedua tanpa jeda
// ditolak 429 (token bucket habis). Test cepat, tanpa sleep lama.
func TestExecuteRateLimitLimited(t *testing.T) {
	ts, bundle := newLocalTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	bundle.RateLimitRPS = 1
	eng := mustEngine(t, bundle)

	_, denial, err := eng.Execute(context.Background(), Request{URL: localURL(ts) + "/1", Method: "GET"})
	if err != nil || denial != nil {
		t.Fatalf("eksekusi pertama harus sukses: err=%v denial=%+v", err, denial)
	}
	_, denial, err = eng.Execute(context.Background(), Request{URL: localURL(ts) + "/2", Method: "GET"})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if denial == nil || denial.HTTP != http.StatusTooManyRequests {
		t.Fatalf("mau denial 429, dapat %+v", denial)
	}
}

// TestRedirectNoFollowDefault: redirect TIDAK diikuti (default bundle tanpa
// follow_redirects), namun tetap tercatat.
func TestRedirectNoFollowDefault(t *testing.T) {
	finalHit := atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		finalHit.Add(1)
		fmt.Fprint(w, "final")
	})
	ts, bundle := newLocalTarget(t, mux)
	eng := mustEngine(t, bundle)

	res, denial, err := eng.Execute(context.Background(), Request{URL: localURL(ts) + "/redir", Method: "GET"})
	if err != nil || denial != nil {
		t.Fatalf("Execute error=%v denial=%+v", err, denial)
	}
	if res.Response.Status != http.StatusFound {
		t.Errorf("status = %d, mau 302 (no-follow)", res.Response.Status)
	}
	if res.Redirect.Followed || res.Redirect.Blocked {
		t.Errorf("redirect harus tercatat tanpa diikuti: %+v", res.Redirect)
	}
	if res.Redirect.Location == "" {
		t.Error("location redirect wajib tercatat")
	}
	if res.Redirect.Location != localURL(ts)+"/final" {
		t.Errorf("location = %q, mau %q", res.Redirect.Location, localURL(ts)+"/final")
	}
	if finalHit.Load() != 0 {
		t.Errorf("/final dipanggil %d kali, mau 0 (no-follow)", finalHit.Load())
	}
}

// TestRedirectFollowOutOfScopeBlocked: follow_redirects=true, redirect ke
// host di luar scope -> berhenti, tandai blocked, target out-of-scope tidak
// pernah dihubungi (§11).
func TestRedirectFollowOutOfScopeBlocked(t *testing.T) {
	outHit := atomic.Int32{}
	// Server kedua = "out of scope" (portnya tidak ada di allowlist).
	outTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outHit.Add(1)
		fmt.Fprint(w, "rahasia out-of-scope")
	}))
	defer outTS.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, localURL(outTS)+"/evil", http.StatusFound)
	})
	ts, bundle := newLocalTarget(t, mux)
	bundle.FollowRedirects = true
	eng := mustEngine(t, bundle)

	res, denial, err := eng.Execute(context.Background(), Request{URL: localURL(ts) + "/redir", Method: "GET"})
	if err != nil || denial != nil {
		t.Fatalf("Execute error=%v denial=%+v", err, denial)
	}
	if res.Response.Status != http.StatusFound {
		t.Errorf("status = %d, mau 302 (response in-scope terakhir)", res.Response.Status)
	}
	if !res.Redirect.Blocked {
		t.Errorf("redirect harus blocked: %+v", res.Redirect)
	}
	if res.Redirect.Reason != "out_of_scope" {
		t.Errorf("reason = %q, mau out_of_scope", res.Redirect.Reason)
	}
	if res.Redirect.Followed {
		t.Error("redirect out-of-scope tidak boleh diikuti")
	}
	if res.Redirect.Location != localURL(outTS)+"/evil" {
		t.Errorf("location = %q, mau %q", res.Redirect.Location, localURL(outTS)+"/evil")
	}
	if outHit.Load() != 0 {
		t.Errorf("target out-of-scope dipanggil %d kali, mau 0", outHit.Load())
	}
	// Bukti redirect blocked masuk evidence (§11 Hard Requirements).
	data, err := os.ReadFile(filepath.Join(eng.EvidenceDir(), res.EvidenceRef))
	if err != nil {
		t.Fatalf("baca evidence: %v", err)
	}
	var ef evidenceFile
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	if !ef.Redirect.Blocked || ef.Redirect.Reason != "out_of_scope" {
		t.Errorf("evidence redirect = %+v, mau blocked/out_of_scope", ef.Redirect)
	}
}

// TestRedirectFollowedInScope: follow_redirects=true, redirect ke path yang
// sama (in-scope) -> diikuti, response final 200, POST dikonversi GET per
// semantik 302.
func TestRedirectFollowedInScope(t *testing.T) {
	var finalMethod, finalBodyLen string
	mux := http.NewServeMux()
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		finalMethod = r.Method
		fmt.Fprint(w, "halaman final")
		finalBodyLen = "na"
	})
	ts, bundle := newLocalTarget(t, mux)
	bundle.FollowRedirects = true
	eng := mustEngine(t, bundle)

	res, denial, err := eng.Execute(context.Background(), Request{
		URL: localURL(ts) + "/redir", Method: "POST", Body: "payload=1"})
	if err != nil || denial != nil {
		t.Fatalf("Execute error=%v denial=%+v", err, denial)
	}
	if res.Response.Status != 200 {
		t.Errorf("status final = %d, mau 200", res.Response.Status)
	}
	if res.Response.Body != "halaman final" {
		t.Errorf("body final = %q", res.Response.Body)
	}
	if !res.Redirect.Followed || res.Redirect.Blocked {
		t.Errorf("redirect harus followed: %+v", res.Redirect)
	}
	if res.Redirect.Hops != 1 {
		t.Errorf("hops = %d, mau 1", res.Redirect.Hops)
	}
	if finalMethod != http.MethodGet {
		t.Errorf("method redirect = %q, mau GET (302 + POST -> GET)", finalMethod)
	}
	_ = finalBodyLen
}

// TestHeaderRedaction: header sensitif pada request DAN response diredaksi
// sebelum keluar dari proxy, tetapi credential asli tetap diteruskan ke target.
func TestHeaderRedaction(t *testing.T) {
	var receivedAuth, receivedKey string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedKey = r.Header.Get("X-Api-Key")
		w.Header().Set("Set-Cookie", "session=super-secret; HttpOnly")
		w.Header().Set("X-Api-Key", "target-key-999")
		w.Header().Set("X-Session-Token", "tok-777")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	})
	ts, bundle := newLocalTarget(t, mux)
	eng := mustEngine(t, bundle)

	res, denial, err := eng.Execute(context.Background(), Request{
		URL:    localURL(ts) + "/auth",
		Method: "GET",
		Headers: map[string]string{
			"Authorization": "Bearer real-token-value",
			"X-Api-Key":     "real-api-key",
			"X-Custom":      "plain-value",
		},
	})
	if err != nil || denial != nil {
		t.Fatalf("Execute error=%v denial=%+v", err, denial)
	}

	// Credential asli harus benar-benar sampai ke target (proxy meneruskan,
	// bukan menghapus).
	if receivedAuth != "Bearer real-token-value" {
		t.Errorf("target menerima Authorization = %q", receivedAuth)
	}
	if receivedKey != "real-api-key" {
		t.Errorf("target menerima X-Api-Key = %q", receivedKey)
	}

	// TAPI yang keluar dari proxy (ke reasoning) harus diredaksi.
	if got := res.Response.Headers.Get("Set-Cookie"); got != RedactedValue {
		t.Errorf("response Set-Cookie = %q, mau %q", got, RedactedValue)
	}
	if got := res.Response.Headers.Get("X-Api-Key"); got != RedactedValue {
		t.Errorf("response X-Api-Key = %q, mau %q", got, RedactedValue)
	}
	if got := res.Response.Headers.Get("X-Session-Token"); got != RedactedValue {
		t.Errorf("response X-Session-Token = %q, mau %q", got, RedactedValue)
	}
	if got := res.Response.Headers.Get("Content-Type"); got != "text/plain" {
		t.Errorf("response Content-Type = %q, tidak boleh diredaksi", got)
	}

	// Evidence juga wajib diredaksi (header request & response).
	data, err := os.ReadFile(filepath.Join(eng.EvidenceDir(), res.EvidenceRef))
	if err != nil {
		t.Fatalf("baca evidence: %v", err)
	}
	var ef evidenceFile
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	for name, want := range map[string]string{
		"Authorization": RedactedValue,
		"X-Api-Key":     RedactedValue,
	} {
		if got := ef.Request.Headers.Get(name); got != want {
			t.Errorf("evidence request %s = %q, mau %q", name, got, want)
		}
	}
	if got := ef.Response.Headers.Get("Set-Cookie"); got != RedactedValue {
		t.Errorf("evidence response Set-Cookie = %q, mau %q", got, RedactedValue)
	}
	if ef.RawContains("real-token-value") || ef.RawContains("target-key-999") {
		t.Error("credential mentah tidak boleh ada di evidence")
	}
}

// TestInlineTruncationAndEvidenceFullBody: body melebihi context budget
// di-truncate inline dengan truncated=true; evidence menyimpan body penuh.
func TestInlineTruncationAndEvidenceFullBody(t *testing.T) {
	long := make([]byte, 0, 200)
	for i := 0; i < 200; i++ {
		long = append(long, byte('a'+i%26))
	}
	ts, bundle := newLocalTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(long)
	}))
	bundle.MaxBodyBytes = 16
	eng := mustEngine(t, bundle)

	res, denial, err := eng.Execute(context.Background(), Request{URL: localURL(ts) + "/big", Method: "GET"})
	if err != nil || denial != nil {
		t.Fatalf("Execute error=%v denial=%+v", err, denial)
	}
	if !res.Response.Truncated {
		t.Error("truncated harus true")
	}
	if len(res.Response.Body) != 16 {
		t.Errorf("len(body inline) = %d, mau 16", len(res.Response.Body))
	}
	if len(res.FullBody) != 200 {
		t.Errorf("len(full body) = %d, mau 200", len(res.FullBody))
	}
	// Evidence memuat body penuh (base64).
	data, err := os.ReadFile(filepath.Join(eng.EvidenceDir(), res.EvidenceRef))
	if err != nil {
		t.Fatalf("baca evidence: %v", err)
	}
	var ef evidenceFile
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	full, err := base64.StdEncoding.DecodeString(ef.Response.BodyBase64)
	if err != nil {
		t.Fatalf("decode body evidence: %v", err)
	}
	if len(full) != 200 {
		t.Errorf("body penuh di evidence = %d byte, mau 200", len(full))
	}
}

// TestMethodValidation: method tidak diizinkan / url kosong ditolak 400.
func TestMethodValidation(t *testing.T) {
	ts, bundle := newLocalTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	eng := mustEngine(t, bundle)
	for _, tc := range []Request{
		{URL: localURL(ts) + "/", Method: "TRACE"},
		{URL: localURL(ts) + "/", Method: ""},
		{URL: "", Method: "GET"},
		{URL: "::::", Method: "GET"},
	} {
		_, denial, err := eng.Execute(context.Background(), tc)
		if err != nil {
			t.Fatalf("Execute error: %v", err)
		}
		if denial == nil || denial.HTTP != http.StatusBadRequest {
			t.Errorf("request %+v mau denial 400, dapat %+v", tc, denial)
		}
	}
}

// RawContains membantu assertion string pada evidence mentah.
func (ef evidenceFile) RawContains(s string) bool {
	data, _ := json.Marshal(ef)
	return strings.Contains(string(data), s)
}
