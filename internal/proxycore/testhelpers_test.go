package proxycore

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const validBundleJSON = `{"version":1,"allowed_hosts":["api.example.com:443"],"max_requests":50,"rate_limit_rps":1}`

func writeBundle(t *testing.T, content string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis bundle: %v", err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

func mustLoadBundle(t *testing.T, content string) *Bundle {
	t.Helper()
	path, sha := writeBundle(t, content)
	b, err := LoadBundle(path, sha)
	if err != nil {
		t.Fatalf("LoadBundle error: %v", err)
	}
	return b
}

func mustEngine(t *testing.T, b *Bundle) *Engine {
	t.Helper()
	eng, err := NewEngine(b, Options{EvidenceDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	return eng
}

// newLocalTarget menjalankan target HTTP lokal (httptest, 127.0.0.1) dan
// mengembalikan bundle yang allowlist-nya memuat "localhost:<port>" — host
// "localhost" dipakai (bukan literal IP) karena internal/scope menolak keras
// IP loopback/rpc1918; testing tetap 100% lokal.
func newLocalTarget(t *testing.T, handler http.Handler) (*httptest.Server, *Bundle) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	u := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	port := portOfURL(t, u)
	b := &Bundle{
		Version:      1,
		AllowedHosts: []string{"localhost:" + port},
		MaxRequests:  50,
		RateLimitRPS: 100,
	}
	return ts, b
}

func portOfURL(t *testing.T, raw string) string {
	t.Helper()
	i := strings.LastIndex(raw, ":")
	if i < 0 {
		t.Fatalf("port tidak ditemukan di %q", raw)
	}
	if _, err := strconv.Atoi(raw[i+1:]); err != nil {
		t.Fatalf("port tidak valid di %q: %v", raw, err)
	}
	return raw[i+1:]
}

func localURL(ts *httptest.Server) string {
	return strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
}

// writeRaw menimpa file dengan konten apa pun (dipakai untuk tamper test).
func writeRaw(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
