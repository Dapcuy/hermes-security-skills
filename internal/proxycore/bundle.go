// Package proxycore berisi engine eksekusi HTTP hermes-proxy (ROADMAP §11, §38).
//
// Semua policy dievaluasi IN-LINE saat eksekusi (TOCTOU guard, §11 prinsip 3):
// scope check, rate limit, dan budget dijalankan di jalur yang sama dengan
// pengiriman request — bukan hanya saat planning di control plane.
// Prinsip fail-closed: bundle tidak valid / hash mismatch = semua operasi
// ditolak. Stdlib only.
package proxycore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Konstanta default bundle (backward-compatible, aman).
const (
	BundleVersion        = 1
	DefaultTimeoutSecond = 15   // timeout per request bila bundle tidak menyebut
	DefaultMaxBodyBytes  = 8192 // context budget inline body (§24/§25)
	MaxTimeoutSeconds    = 300
	MaxBundleBodyBytes   = 10 << 20 // 10 MiB — batas validasi nilai bundle
)

// Bundle adalah policy bundle in-line (ROADMAP §11): di-mount read-only ke
// container proxy dan diverifikasi sha256-nya sebelum dipakai.
//
// Field FollowRedirects / TimeoutSeconds / MaxBodyBytes bersifat OPSIONAL dan
// backward-compatible: bundle lama tanpa field tersebut tetap valid dan
// memakai default aman (no-follow redirects, 15s, 8192 byte).
type Bundle struct {
	Version      int      `json:"version"`
	AllowedHosts []string `json:"allowed_hosts"`
	MaxRequests  int      `json:"max_requests"`
	RateLimitRPS int      `json:"rate_limit_rps"`

	// Field baru (opsional, default aman):
	FollowRedirects bool `json:"follow_redirects,omitempty"` // default false (§11: redirect no-follow)
	TimeoutSeconds  int  `json:"timeout_seconds,omitempty"`  // default 15
	MaxBodyBytes    int  `json:"max_body_bytes,omitempty"`   // default 8192
}

// LoadBundle membaca bundle, memverifikasi sha256 (fail-closed bila mismatch
// atau hash kosong), lalu memvalidasi isinya.
func LoadBundle(path, wantSHA string) (*Bundle, error) {
	if strings.TrimSpace(wantSHA) == "" {
		return nil, errors.New("proxycore: --bundle-sha256 wajib diisi (fail-closed: bundle tanpa hash terverifikasi ditolak)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("proxycore: baca bundle %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, strings.TrimSpace(wantSHA)) {
		return nil, fmt.Errorf("proxycore: bundle sha256 mismatch (got %s, want %s) — fail-closed", got, wantSHA)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("proxycore: parse bundle %s: %w", path, err)
	}
	if b.Version != BundleVersion {
		return nil, fmt.Errorf("proxycore: bundle version %d tidak didukung", b.Version)
	}
	if len(b.AllowedHosts) == 0 {
		return nil, errors.New("proxycore: bundle allowed_hosts kosong — fail-closed")
	}
	if b.MaxRequests <= 0 || b.RateLimitRPS <= 0 {
		return nil, errors.New("proxycore: bundle max_requests dan rate_limit_rps harus > 0")
	}
	if b.TimeoutSeconds < 0 || b.TimeoutSeconds > MaxTimeoutSeconds {
		return nil, fmt.Errorf("proxycore: timeout_seconds harus 1..%d (0 = default %d)", MaxTimeoutSeconds, DefaultTimeoutSecond)
	}
	if b.MaxBodyBytes < 0 || b.MaxBodyBytes > MaxBundleBodyBytes {
		return nil, fmt.Errorf("proxycore: max_body_bytes harus 1..%d (0 = default %d)", MaxBundleBodyBytes, DefaultMaxBodyBytes)
	}
	return &b, nil
}

// Timeout mengembalikan timeout efektif per request HTTP.
func (b *Bundle) Timeout() time.Duration {
	if b.TimeoutSeconds <= 0 {
		return DefaultTimeoutSecond * time.Second
	}
	return time.Duration(b.TimeoutSeconds) * time.Second
}

// MaxBodyBytesOrDefault mengembalikan context budget inline body (§24).
func (b *Bundle) MaxBodyBytesOrDefault() int {
	if b.MaxBodyBytes <= 0 {
		return DefaultMaxBodyBytes
	}
	return b.MaxBodyBytes
}

// ScopeChecker adalah kontrak scope matching (diimplementasikan oleh
// internal/scope.Checker). Interface agar engine testable dan agar jalur
// MITM memakai scope yang persis sama.
type ScopeChecker interface {
	Check(rawURL string) error
}

// allowedMethods: daftar method HTTP yang boleh direplay.
var allowedMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
}
