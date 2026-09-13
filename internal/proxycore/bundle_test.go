package proxycore

import (
	"strings"
	"testing"
	"time"
)

func TestLoadBundle(t *testing.T) {
	path, sha := writeBundle(t, validBundleJSON)
	b, err := LoadBundle(path, sha)
	if err != nil {
		t.Fatalf("LoadBundle error: %v", err)
	}
	if b.Version != 1 || b.MaxRequests != 50 || b.RateLimitRPS != 1 || len(b.AllowedHosts) != 1 {
		t.Errorf("bundle tidak sesuai: %+v", b)
	}
	// Hash mismatch = fail-closed.
	if _, err := LoadBundle(path, strings.Repeat("a", 64)); err == nil {
		t.Error("hash mismatch harus error")
	}
	// Hash kosong = fail-closed.
	if _, err := LoadBundle(path, ""); err == nil {
		t.Error("hash kosong harus error")
	}
	// Bundle diubah setelah hash dihitung = fail-closed (tamper test).
	tampered := strings.Replace(validBundleJSON, "50", "500", 1)
	path2, sha2 := writeBundle(t, validBundleJSON)
	if _, err := LoadBundle(path2, sha2); err != nil {
		t.Fatalf("LoadBundle valid error: %v", err)
	}
	if err := writeRaw(path2, tampered); err != nil {
		t.Fatalf("tulis tampered: %v", err)
	}
	if _, err := LoadBundle(path2, sha2); err == nil {
		t.Error("bundle yang diubah harus ditolak (hash mismatch)")
	}
}

func TestLoadBundleFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"version tak dikenal", `{"version":2,"allowed_hosts":["a.com"],"max_requests":1,"rate_limit_rps":1}`},
		{"allowed_hosts kosong", `{"version":1,"allowed_hosts":[],"max_requests":1,"rate_limit_rps":1}`},
		{"max_requests 0", `{"version":1,"allowed_hosts":["a.com"],"max_requests":0,"rate_limit_rps":1}`},
		{"rate_limit 0", `{"version":1,"allowed_hosts":["a.com"],"max_requests":1,"rate_limit_rps":0}`},
		{"field tidak dikenal", `{"version":1,"allowed_hosts":["a.com"],"max_requests":1,"rate_limit_rps":1,"extra":true}`},
		{"timeout negatif", `{"version":1,"allowed_hosts":["a.com"],"max_requests":1,"rate_limit_rps":1,"timeout_seconds":-1}`},
		{"timeout terlalu besar", `{"version":1,"allowed_hosts":["a.com"],"max_requests":1,"rate_limit_rps":1,"timeout_seconds":9999}`},
		{"max_body_bytes negatif", `{"version":1,"allowed_hosts":["a.com"],"max_requests":1,"rate_limit_rps":1,"max_body_bytes":-5}`},
		{"max_body_bytes terlalu besar", `{"version":1,"allowed_hosts":["a.com"],"max_requests":1,"rate_limit_rps":1,"max_body_bytes":99999999}`},
		{"bukan json", `bukan json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, sha := writeBundle(t, tc.content)
			if _, err := LoadBundle(path, sha); err == nil {
				t.Error("harus error (fail-closed)")
			}
		})
	}
	// File hilang.
	if _, err := LoadBundle(t.TempDir()+"/nope.json", strings.Repeat("a", 64)); err == nil {
		t.Error("bundle hilang harus error")
	}
}

// TestBundleBackwardCompatibleDefaults: bundle lama TANPA field baru tetap
// valid dan mendapat default aman (no-follow, 15s, 8192 byte).
func TestBundleBackwardCompatibleDefaults(t *testing.T) {
	b := mustLoadBundle(t, validBundleJSON)
	if b.FollowRedirects {
		t.Error("follow_redirects default harus false (no-follow, §11)")
	}
	if b.Timeout() != 15*time.Second {
		t.Errorf("timeout default = %s, mau 15s", b.Timeout())
	}
	if b.MaxBodyBytesOrDefault() != 8192 {
		t.Errorf("max_body_bytes default = %d, mau 8192", b.MaxBodyBytesOrDefault())
	}
}

// TestBundleNewFieldsOptional: field baru (follow_redirects, timeout_seconds,
// max_body_bytes) opsional dan dihormati bila diisi.
func TestBundleNewFieldsOptional(t *testing.T) {
	b := mustLoadBundle(t, `{"version":1,"allowed_hosts":["a.com:443"],"max_requests":5,"rate_limit_rps":2,"follow_redirects":true,"timeout_seconds":30,"max_body_bytes":1024}`)
	if !b.FollowRedirects {
		t.Error("follow_redirects=true harus dibaca")
	}
	if b.Timeout() != 30*time.Second {
		t.Errorf("timeout = %s, mau 30s", b.Timeout())
	}
	if b.MaxBodyBytesOrDefault() != 1024 {
		t.Errorf("max_body_bytes = %d, mau 1024", b.MaxBodyBytesOrDefault())
	}
}
