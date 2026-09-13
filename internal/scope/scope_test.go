package scope

import (
	"errors"
	"net"
	"testing"
)

func mustChecker(t *testing.T, entries []string) *Checker {
	t.Helper()
	c, err := NewChecker(entries)
	if err != nil {
		t.Fatalf("NewChecker(%v) error: %v", entries, err)
	}
	return c
}

func TestExactHostMatch(t *testing.T) {
	c := mustChecker(t, []string{"example.com", "api.example.com:443"})
	ok := []string{
		"https://example.com/",
		"http://example.com", // port default 80
		"https://EXAMPLE.com/path?x=1",
		"https://example.com./",   // trailing dot dinormalisasi
		"https://api.example.com", // port default 443 sesuai entry :443
	}
	for _, u := range ok {
		if err := c.Check(u); err != nil {
			t.Errorf("Check(%q) = %v, mau diizinkan", u, err)
		}
	}
}

func TestSubstringBypassTerkunci(t *testing.T) {
	// Kasus eksplisit dari spesifikasi: hostname harus exact, bukan substring.
	c := mustChecker(t, []string{"example.com"})
	deny := []string{
		"https://evil-example.com/",         // substring "example.com" tapi beda host
		"https://example.com.attacker.tld/", // host target jadi subdomain attacker
		"https://example.com.evil.com/",
		"https://notexample.com/",
	}
	for _, u := range deny {
		err := c.Check(u)
		if err == nil {
			t.Errorf("Check(%q) harus DITOLAK (substring bypass)", u)
			continue
		}
		if !errors.Is(err, ErrHostNotAllowed) {
			t.Errorf("Check(%q) error salah: %v", u, err)
		}
	}
}

func TestWildcardSingleLevel(t *testing.T) {
	c := mustChecker(t, []string{"*.example.com"})
	ok := []string{
		"https://foo.example.com/",
		"https://a.example.com/x",
		"https://FOO.EXAMPLE.COM/",
	}
	for _, u := range ok {
		if err := c.Check(u); err != nil {
			t.Errorf("Check(%q) = %v, mau diizinkan", u, err)
		}
	}
	deny := []string{
		"https://example.com/",      // apex tidak dicakup wildcard
		"https://a.b.example.com/",  // dua level tidak dicakup
		"https://evil-example.com/", // label tidak exact
		"https://example.com.attacker.tld/",
	}
	for _, u := range deny {
		if err := c.Check(u); err == nil {
			t.Errorf("Check(%q) harus DITOLAK", u)
		}
	}
}

func TestPortCheck(t *testing.T) {
	c := mustChecker(t, []string{"example.com", "api.example.com:8443"})
	// Port non-default vs entry tanpa port -> tolak (fail-closed).
	if err := c.Check("http://example.com:8080/"); !errors.Is(err, ErrPortNotAllowed) {
		t.Errorf("port 8080 dengan entry tanpa port harus ErrPortNotAllowed, dapat %v", err)
	}
	// Entry dengan port eksplisit.
	if err := c.Check("https://api.example.com:8443/"); err != nil {
		t.Errorf("Check api:8443 = %v, mau ok", err)
	}
	if err := c.Check("https://api.example.com:9443/"); !errors.Is(err, ErrPortNotAllowed) {
		t.Errorf("port 9443 harus ditolak, dapat %v", err)
	}
	// Entry :8443 tidak otomatis membolehkan port default lain.
	if err := c.Check("https://api.example.com/"); !errors.Is(err, ErrPortNotAllowed) {
		t.Errorf("https api tanpa port harus ditolak (entry hanya :8443), dapat %v", err)
	}
}

func TestPrivateIPDeniedWalauDiAllowlist(t *testing.T) {
	// Deny keras: allowlist berisi IP privat pun tetap ditolak.
	c := mustChecker(t, []string{"10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.169.254"})
	privat := []string{
		"http://10.0.0.5/",
		"http://172.16.0.1/",
		"http://172.31.255.255/",
		"http://192.168.1.1/",
		"http://127.0.0.1:8080/",
		"http://[::1]/",
		"http://[fe80::1]/",
		"http://[fd00::1]/",
		"http://0.0.0.0/",
		"http://100.64.0.1/",
		"https://[::ffff:10.0.0.1]/", // IPv4-mapped IPv6 -> IPv4 privat
	}
	for _, u := range privat {
		err := c.Check(u)
		if !errors.Is(err, ErrPrivateAddress) {
			t.Errorf("Check(%q) = %v, mau ErrPrivateAddress", u, err)
		}
	}
}

func TestCloudMetadataDenied(t *testing.T) {
	c := mustChecker(t, []string{"169.254.169.254", "example.com"})
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254:80/",
		"https://[fd00:ec2::254]/",
	} {
		err := c.Check(u)
		if !errors.Is(err, ErrMetadataAddress) {
			t.Errorf("Check(%q) = %v, mau ErrMetadataAddress", u, err)
		}
	}
}

func TestPublicIPDenganAllowlist(t *testing.T) {
	c := mustChecker(t, []string{"8.8.8.8"})
	if err := c.Check("https://8.8.8.8/dns-query"); err != nil {
		t.Errorf("Check(8.8.8.8) = %v, mau ok", err)
	}
	if err := c.Check("https://9.9.9.9/"); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("Check(9.9.9.9) = %v, mau ErrHostNotAllowed", err)
	}
}

func TestHostOutOfScope(t *testing.T) {
	c := mustChecker(t, []string{"example.com"})
	if err := c.Check("https://other.com/"); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("Check(other.com) = %v, mau ErrHostNotAllowed", err)
	}
}

func TestURLInvalidFailClosed(t *testing.T) {
	c := mustChecker(t, []string{"example.com"})
	cases := []struct {
		url  string
		want error
	}{
		{"ftp://example.com/", ErrUnsupportedScheme},
		{"file:///etc/passwd", ErrUnsupportedScheme},
		{"https://user:pass@example.com/", ErrUserInfo},
		{"https://user@example.com/", ErrUserInfo},
		{"://no-scheme", ErrInvalidURL},
		{"https://", ErrInvalidURL},
	}
	for _, tc := range cases {
		err := c.Check(tc.url)
		if !errors.Is(err, tc.want) {
			t.Errorf("Check(%q) = %v, mau %v", tc.url, err, tc.want)
		}
	}
}

func TestNewCheckerFailClosed(t *testing.T) {
	for _, bad := range []string{"", "  ", "bad host", "a.b.*.c", "*.example.*", "host:"} {
		if _, err := NewChecker([]string{"ok.com", bad}); err == nil {
			t.Errorf("NewChecker entry %q harus error", bad)
		}
	}
	c, err := NewChecker(nil)
	if err != nil {
		t.Fatalf("NewChecker(nil) error: %v", err)
	}
	if err := c.Check("https://example.com/"); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("allowlist kosong harus menolak semua, dapat %v", err)
	}
}

func TestIsDeniedIPUnits(t *testing.T) {
	denied := []string{
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1",
		"127.0.0.1", "169.254.0.1", "169.254.169.254", "0.0.0.0",
		"100.64.0.1", "100.127.255.255", "::1", "fe80::1", "fd00::1", "::",
	}
	for _, s := range denied {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %s bukan IP", s)
		}
		if !IsDeniedIP(ip) {
			t.Errorf("IsDeniedIP(%s) = false, mau true", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.0.1", "192.169.0.1", "2606:4700::1111"}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %s bukan IP", s)
		}
		if IsDeniedIP(ip) {
			t.Errorf("IsDeniedIP(%s) = true, mau false", s)
		}
	}
	if !IsDeniedIP(nil) {
		t.Error("IsDeniedIP(nil) harus true (fail-closed)")
	}
	if !IsCloudMetadata(net.ParseIP("169.254.169.254")) {
		t.Error("169.254.169.254 harus terdeteksi metadata")
	}
	if IsCloudMetadata(net.ParseIP("169.254.169.253")) {
		t.Error("169.254.169.253 bukan metadata")
	}
}

func TestValidateConvenience(t *testing.T) {
	if err := Validate("https://example.com/", []string{"example.com"}); err != nil {
		t.Errorf("Validate ok gagal: %v", err)
	}
	if err := Validate("::bad-url::", []string{"example.com"}); err == nil {
		t.Error("Validate URL rusak harus error")
	}
}
