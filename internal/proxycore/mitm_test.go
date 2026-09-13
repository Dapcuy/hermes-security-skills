package proxycore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// selfSignedCertForLocalhost: sertifikat self-signed untuk target TLS lokal
// (testing saja). Client uji memasang cert ini sebagai root.
func selfSignedCertForLocalhost(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key target: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("buat cert target: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newLocalTLSTarget: server TLS lokal di 127.0.0.1 dengan cert untuk
// "localhost" (scope matcher menolak literal IP loopback, jadi client uji
// memakai hostname localhost — tetap 100% lokal).
func newLocalTLSTarget(t *testing.T, handler http.Handler) (targetURL string, rootPool *x509.CertPool) {
	t.Helper()
	cert := selfSignedCertForLocalhost(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TLS target: %v", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() { _ = srv.Close() })
	pool := x509.NewCertPool()
	for _, der := range cert.Certificate {
		pool.AddCert(mustParseCert(t, der))
	}
	port := portOfURL(t, "http://x:"+itoa(ln.Addr().(*net.TCPAddr).Port))
	return "https://localhost:" + port, pool
}

func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }

// TestGenerateCAAndCertPEM: CA ephemeral valid, PEM yang diekspor hanya
// berisi sertifikat publik (tanpa private key).
func TestGenerateCAAndCertPEM(t *testing.T) {
	ca, err := GenerateCA(time.Now())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if !ca.Cert.IsCA {
		t.Error("CA harus IsCA")
	}
	if ca.Cert.NotAfter.Sub(ca.Cert.NotBefore) > caValidity+2*time.Hour {
		t.Errorf("validitas CA terlalu panjang: %s", ca.Cert.NotAfter.Sub(ca.Cert.NotBefore))
	}
	pemData := ca.CertPEM()
	block, rest := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("PEM CA tidak valid: %q", string(pemData))
	}
	if len(rest) != 0 || strings.Contains(string(pemData), "PRIVATE KEY") {
		t.Error("ekspor CA TIDAK boleh memuat private key")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Errorf("PEM CA gagal di-parse: %v", err)
	}
}

// TestMITMHandshakeAndCapture: handshake TLS MITM end-to-end dengan client Go
// + custom RootCAs (bukan browser): CONNECT -> leaf per SNI -> policy in-line
// -> capture evidence. Ini uji WAJIB Mode 2 (§38 item 7.5).
func TestMITMHandshakeAndCapture(t *testing.T) {
	targetHit := atomic.Int32{}
	targetMux := http.NewServeMux()
	targetMux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		targetHit.Add(1)
		w.Header().Set("Set-Cookie", "session=server-secret; HttpOnly")
		fmt.Fprintf(w, "authorization diterima: %s", r.Header.Get("Authorization"))
	})
	targetURL, targetRoots := newLocalTLSTarget(t, targetMux)
	targetPort := portOfURL(t, strings.Replace(targetURL, "https://", "http://", 1))

	bundle := &Bundle{
		Version:      1,
		AllowedHosts: []string{"localhost:" + targetPort},
		MaxRequests:  10,
		RateLimitRPS: 100,
	}
	evDir := t.TempDir()
	eng, err := NewEngine(bundle, Options{EvidenceDir: evDir, TLSRootCAs: targetRoots})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ca, err := GenerateCA(time.Now())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	mitm := httptest.NewServer(NewMITMProxy(ca, eng))
	defer mitm.Close()
	proxyURL, err := url.Parse(mitm.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS12,
		},
	}}
	defer client.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, targetURL+"/secret", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer real-mitm-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request via MITM gagal (handshake/capture rusak): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status via MITM = %d, mau 200", resp.StatusCode)
	}
	body := make([]byte, 512)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "Bearer real-mitm-token") {
		t.Errorf("body via MITM = %q — credential asli harus diteruskan ke target", string(body[:n]))
	}
	if targetHit.Load() != 1 {
		t.Errorf("target dipanggil %d kali, mau 1", targetHit.Load())
	}

	// Evidence tercatat: header sensitif diredaksi, URL intercept benar.
	entries, err := os.ReadDir(evDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("evidence MITM tidak tertulis (err=%v, entries=%d)", err, len(entries))
	}
	data, err := os.ReadFile(filepath.Join(evDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("baca evidence: %v", err)
	}
	var ef evidenceFile
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	if ef.Request.URL != targetURL+"/secret" {
		t.Errorf("evidence URL = %q, mau %q", ef.Request.URL, targetURL+"/secret")
	}
	if ef.Request.Method != http.MethodGet {
		t.Errorf("evidence method = %q", ef.Request.Method)
	}
	if got := ef.Request.Headers.Get("Authorization"); got != RedactedValue {
		t.Errorf("evidence request Authorization = %q, mau %q", got, RedactedValue)
	}
	if got := ef.Response.Headers.Get("Set-Cookie"); got != RedactedValue {
		t.Errorf("evidence response Set-Cookie = %q, mau %q", got, RedactedValue)
	}
	if ef.Response.Status != http.StatusOK {
		t.Errorf("evidence status = %d", ef.Response.Status)
	}
}

// TestMITMScopeDeniedInTunnel: request hasil intercept ke host di luar
// allowlist ditolak 403 oleh jalur policy yang sama, tanpa menyentuh target.
func TestMITMScopeDeniedInTunnel(t *testing.T) {
	outHit := atomic.Int32{}
	// Target kedua = out-of-scope (portnya tidak di allowlist).
	outTargetURL, _ := newLocalTLSTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outHit.Add(1)
		fmt.Fprint(w, "tidak boleh")
	}))
	outPort := portOfURL(t, strings.Replace(outTargetURL, "https://", "http://", 1))

	// Request akan ditolak scope SEBELUM dial, jadi engine tidak butuh
	// TLS roots khusus.
	bundle := &Bundle{
		Version:      1,
		AllowedHosts: []string{"localhost:1"}, // port 1 = tidak pernah dipakai target nyata
		MaxRequests:  10,
		RateLimitRPS: 100,
	}
	eng, err := NewEngine(bundle, Options{EvidenceDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ca, err := GenerateCA(time.Now())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	mitm := httptest.NewServer(NewMITMProxy(ca, eng))
	defer mitm.Close()
	proxyURL, _ := url.Parse(mitm.URL)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}}
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://localhost:" + outPort + "/evil")
	if err != nil {
		t.Fatalf("request via MITM gagal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, mau 403 (denied in tunnel)", resp.StatusCode)
	}
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	var m map[string]string
	if err := json.Unmarshal(buf[:n], &m); err != nil || m["status"] != "denied" {
		t.Errorf("body = %q, mau {\"status\":\"denied\"}", string(buf[:n]))
	}
	if outHit.Load() != 0 {
		t.Errorf("target out-of-scope dipanggil %d kali, mau 0", outHit.Load())
	}
}

// TestMITMLeafPerSNI: leaf certificate di-generate dinamis per hostname dan
// di-cache (dua request ke host yang sama memakai leaf yang sama).
func TestMITMLeafPerSNI(t *testing.T) {
	ca, err := GenerateCA(time.Now())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	bundle := &Bundle{Version: 1, AllowedHosts: []string{"localhost:443"}, MaxRequests: 5, RateLimitRPS: 100}
	eng, err := NewEngine(bundle, Options{EvidenceDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	m := NewMITMProxy(ca, eng)

	leaf1, err := m.leafFor("host-a.example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	leaf2, err := m.leafFor("host-b.example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	leaf1again, err := m.leafFor("host-a.example.com")
	if err != nil {
		t.Fatalf("leafFor cache: %v", err)
	}
	if leaf1 == leaf2 {
		t.Error("leaf dua host berbeda harus berbeda objek")
	}
	if leaf1 != leaf1again {
		t.Error("leaf host sama harus di-cache")
	}
	// Leaf ditandatangani CA dan memuat hostname sebagai DNSName.
	c, err := x509.ParseCertificate(leaf1.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := c.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("leaf tidak ditandatangani CA: %v", err)
	}
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "host-a.example.com" {
		t.Errorf("DNSNames leaf = %v", c.DNSNames)
	}
	if len(leaf1.Certificate) != 2 { // leaf + CA (chain)
		t.Errorf("chain leaf = %d cert, mau 2", len(leaf1.Certificate))
	}
}
