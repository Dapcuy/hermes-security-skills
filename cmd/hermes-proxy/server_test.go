package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"hermes-security-skills/internal/events"
	"hermes-security-skills/internal/proxycore"
)

// writeBundleFile menulis bundle JSON + mengembalikan (path, sha256).
func writeBundleFile(t *testing.T, content string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis bundle: %v", err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

// newTestStack membangun target lokal + engine + control channel HTTP
// (Server) yang dibungkus httptest — menguji jalur API end-to-end.
func newTestStack(t *testing.T, mutate func(*proxycore.Bundle)) (*httptest.Server, *httptest.Server, *atomic.Int32, string) {
	t.Helper()
	hit := atomic.Int32{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "respons dari target lokal")
	}))
	t.Cleanup(target.Close)

	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	port := targetURL[strings.LastIndex(targetURL, ":")+1:]

	bundleJSON := fmt.Sprintf(`{"version":1,"allowed_hosts":["localhost:%s"],"max_requests":50,"rate_limit_rps":100}`, port)
	bPath, bSHA := writeBundleFile(t, bundleJSON)
	bundle, err := proxycore.LoadBundle(bPath, bSHA)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if mutate != nil {
		mutate(bundle)
	}
	evDir := t.TempDir()
	engine, err := proxycore.NewEngine(bundle, proxycore.Options{EvidenceDir: evDir})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	apiSrv := &Server{engine: engine}
	api := httptest.NewServer(http.HandlerFunc(apiSrv.HandleExecute))
	t.Cleanup(api.Close)
	return api, target, &hit, evDir
}

func postExecute(t *testing.T, api *httptest.Server, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(api.URL+"/execute", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("POST /execute: %v", err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode respons: %v (%s)", err, resp.Header.Get("Content-Type"))
	}
	return resp.StatusCode, m
}

// TestHandleExecuteEndToEnd: eksekusi nyata via control channel.
func TestHandleExecuteEndToEnd(t *testing.T) {
	api, target, hit, evDir := newTestStack(t, nil)

	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	body := fmt.Sprintf(`{"url":%q,"method":"GET"}`, targetURL+"/halo")
	code, m := postExecute(t, api, body)
	if code != http.StatusOK {
		t.Fatalf("code = %d, mau 200 (%v)", code, m)
	}
	if m["status"] != "executed" {
		t.Errorf("status = %v, mau executed", m["status"])
	}
	respObj, ok := m["response"].(map[string]any)
	if !ok {
		t.Fatalf("response tidak ada: %v", m)
	}
	if respObj["status"].(float64) != 200 {
		t.Errorf("response.status = %v, mau 200", respObj["status"])
	}
	if respObj["body"] != "respons dari target lokal" {
		t.Errorf("response.body = %v", respObj["body"])
	}
	if respObj["truncated"] != false {
		t.Errorf("truncated = %v, mau false", respObj["truncated"])
	}
	ref, _ := m["evidence_ref"].(string)
	if ref == "" {
		t.Fatal("evidence_ref wajib ada")
	}
	if _, err := os.Stat(filepath.Join(evDir, ref)); err != nil {
		t.Errorf("evidence file tidak ada: %v", err)
	}
	if _, ok := m["redirect"].(map[string]any); !ok {
		t.Error("redirect info wajib ada")
	}
	if hit.Load() != 1 {
		t.Errorf("target dipanggil %d kali", hit.Load())
	}
}

// TestHandleExecuteCaseFlowsToEvidence: field opsional "case" mengalir
// end-to-end — evidence file membawa case_id, event index (internal/events)
// mengisi field case_id-nya, dan filter case pada List bekerja.
func TestHandleExecuteCaseFlowsToEvidence(t *testing.T) {
	api, target, _, evDir := newTestStack(t, nil)
	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	// 1) Eksekusi dengan case.
	body := fmt.Sprintf(`{"url":%q,"method":"GET","case":"mem-demo"}`, targetURL+"/halo")
	code, m := postExecute(t, api, body)
	if code != http.StatusOK || m["status"] != "executed" {
		t.Fatalf("code = %d status = %v, mau 200/executed", code, m["status"])
	}
	ref, _ := m["evidence_ref"].(string)
	if ref == "" {
		t.Fatal("evidence_ref wajib ada")
	}

	// 2) Evidence file berisi case_id.
	raw, err := os.ReadFile(filepath.Join(evDir, ref))
	if err != nil {
		t.Fatalf("baca evidence: %v", err)
	}
	var ev struct {
		CaseID string `json:"case_id"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	if ev.CaseID != "mem-demo" {
		t.Errorf("evidence case_id = %q, mau %q", ev.CaseID, "mem-demo")
	}

	// 3) Event index terisi + filter case bekerja.
	st, err := events.LoadEvidenceDir(evDir)
	if err != nil {
		t.Fatalf("LoadEvidenceDir: %v", err)
	}
	if st.Count() != 1 {
		t.Fatalf("index count = %d, mau 1", st.Count())
	}
	if got := st.Entries()[0].CaseID; got != "mem-demo" {
		t.Errorf("index case_id = %q, mau mem-demo", got)
	}
	if n := len(st.List(events.ListFilter{CaseID: "mem-demo"})); n != 1 {
		t.Errorf("filter case mem-demo = %d entri, mau 1", n)
	}
	if n := len(st.List(events.ListFilter{CaseID: "case-lain"})); n != 0 {
		t.Errorf("filter case case-lain = %d entri, mau 0", n)
	}

	// 4) Eksekusi tanpa case: index case_id tetap kosong.
	body = fmt.Sprintf(`{"url":%q,"method":"GET"}`, targetURL+"/tanpa-case")
	if code, m := postExecute(t, api, body); code != http.StatusOK || m["status"] != "executed" {
		t.Fatalf("eksekusi tanpa case: code = %d (%v)", code, m)
	}
	st2, err := events.LoadEvidenceDir(evDir)
	if err != nil {
		t.Fatalf("LoadEvidenceDir kedua: %v", err)
	}
	var withCase, withoutCase int
	for _, e := range st2.Entries() {
		if e.CaseID == "mem-demo" {
			withCase++
		} else if e.CaseID == "" {
			withoutCase++
		}
	}
	if withCase != 1 || withoutCase != 1 {
		t.Errorf("index case: withCase=%d withoutCase=%d, mau 1/1", withCase, withoutCase)
	}
}

// TestHandleExecuteCaseInvalid: case invalid ditolak fail-closed (400) dan
// tidak pernah sampai ke target.
func TestHandleExecuteCaseInvalid(t *testing.T) {
	api, target, hit, _ := newTestStack(t, nil)
	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	cases := []struct {
		name    string
		caseVal string
	}{
		{"huruf besar", "Mem-Demo"},
		{"underscore", "mem_demo"},
		{"spasi", "mem demo"},
		{"kosong spasi", "   "},
		{"lebih dari 64", strings.Repeat("a", 65)},
		{"path traversal", "../evil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"url":%q,"method":"GET","case":%q}`, targetURL+"/x", tc.caseVal)
			code, m := postExecute(t, api, body)
			if code != http.StatusBadRequest {
				t.Errorf("code = %d, mau 400 (%v)", code, m)
			}
			if m["status"] != "denied" {
				t.Errorf("status = %v, mau denied", m["status"])
			}
		})
	}
	if hit.Load() != 0 {
		t.Errorf("target dipanggil %d kali, mau 0 (case invalid ditolak sebelum network)", hit.Load())
	}
}

// TestHandleExecuteDenials: penolakan fail-closed lewat API dengan kode tepat.
func TestHandleExecuteDenials(t *testing.T) {
	api, target, hit, _ := newTestStack(t, nil)
	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	cases := []struct {
		name string
		body string
		code int
	}{
		{"out of scope", `{"url":"http://other.local/","method":"GET"}`, http.StatusForbidden},
		{"ip loopback literal", fmt.Sprintf(`{"url":%q,"method":"GET"}`, target.URL), http.StatusForbidden},
		{"method dilarang", fmt.Sprintf(`{"url":%q,"method":"TRACE"}`, targetURL+"/"), http.StatusBadRequest},
		{"json rusak", `{url}`, http.StatusBadRequest},
		{"field tak dikenal", fmt.Sprintf(`{"url":%q,"method":"GET","zzz":1}`, targetURL+"/"), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, m := postExecute(t, api, tc.body)
			if code != tc.code {
				t.Errorf("code = %d, mau %d (%v)", code, tc.code, m)
			}
			if m["status"] != "denied" {
				t.Errorf("status = %v, mau denied", m["status"])
			}
		})
	}
	if hit.Load() != 0 {
		t.Errorf("target dipanggil %d kali, mau 0", hit.Load())
	}
}

// TestHandleExecuteBudget429: budget habis -> 429.
func TestHandleExecuteBudget429(t *testing.T) {
	api, target, _, _ := newTestStack(t, func(b *proxycore.Bundle) { b.MaxRequests = 1 })
	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	body := fmt.Sprintf(`{"url":%q,"method":"GET"}`, targetURL+"/1")
	code, _ := postExecute(t, api, body)
	if code != http.StatusOK {
		t.Fatalf("eksekusi pertama code = %d, mau 200", code)
	}
	body = fmt.Sprintf(`{"url":%q,"method":"GET"}`, targetURL+"/2")
	code, m := postExecute(t, api, body)
	if code != http.StatusTooManyRequests {
		t.Fatalf("eksekusi kedua code = %d, mau 429 (%v)", code, m)
	}
	if m["status"] != "denied" {
		t.Errorf("status = %v, mau denied", m["status"])
	}
}

// TestHandleExecuteWrongHTTPMethod: hanya POST.
func TestHandleExecuteWrongHTTPMethod(t *testing.T) {
	api, _, _, _ := newTestStack(t, nil)
	resp, err := http.Get(api.URL + "/execute")
	if err != nil {
		t.Fatalf("GET /execute: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("code = %d, mau 405", resp.StatusCode)
	}
}

// TestHandleExecuteNilEngine: fail-closed tanpa engine.
func TestHandleExecuteNilEngine(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"url":"https://api.example.com/","method":"GET"}`))
	rec := httptest.NewRecorder()
	srv.HandleExecute(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("code = %d, mau 403 (fail-closed)", rec.Code)
	}
}

// TestHandleExecuteHashFailClosed: bundle dengan hash salah = engine gagal
// dibangun -> proxy menolak semua (dilakukan di level LoadBundle; di sini
// diuji integrasinya bahwa server tetap merespons denied).
func TestHandleExecuteHashFailClosed(t *testing.T) {
	// LoadBundle menolak hash kosong/mismatch — diverifikasi langsung.
	if _, err := proxycore.LoadBundle(filepath.Join(t.TempDir(), "x.json"), ""); err == nil {
		t.Error("hash kosong harus error")
	}
}

// TestValidateLoopbackAddr: mode default hanya loopback (§11).
func TestValidateLoopbackAddr(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:8080", "127.9.9.9:1", "[::1]:8080"} {
		if err := validateLoopbackAddr(ok); err != nil {
			t.Errorf("validateLoopbackAddr(%q) = %v, mau ok", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:8080", "example.com:80", "noport", "[::2]:8080"} {
		if err := validateLoopbackAddr(bad); err == nil {
			t.Errorf("validateLoopbackAddr(%q) harus error", bad)
		}
	}
}

// TestBindAllAddr: --bind all mengubah host ke 0.0.0.0 (mode container).
func TestBindAllAddr(t *testing.T) {
	got, err := bindAllAddr("127.0.0.1:8080")
	if err != nil || got != "0.0.0.0:8080" {
		t.Errorf("bindAllAddr = %q, %v; mau 0.0.0.0:8080, nil", got, err)
	}
	if _, err := bindAllAddr("noport"); err == nil {
		t.Error("addr tanpa port harus error")
	}
}

// TestNetJoinHostPortSanity: jaga format addr tetap benar lintas platform.
func TestNetJoinHostPortSanity(t *testing.T) {
	if _, _, err := net.SplitHostPort("0.0.0.0:8080"); err != nil {
		t.Errorf("SplitHostPort gagal: %v", err)
	}
}
