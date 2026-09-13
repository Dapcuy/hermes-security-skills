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

// ---------------------------------------------------------------------------
// Adversarial tests (security review): setiap kasus di bawah adalah vektor
// serangan nyata. Yang lulus = bypass yang harus diperbaiki di scope.go.
// ---------------------------------------------------------------------------

// TestAdversarialScopeIPObfuscation: representasi numerik non-standar yang
// DITERIMA resolver OS (inet_aton / getaddrinfo) — desimal penuh, hex, oktal,
// bentuk pendek — beserta alamat transisi IPv6 yang membawa IPv4 ter-embed
// (IPv4-mapped, NAT64 64:ff9b::/96, 6to4 2002::/16) HARUS ditolak keras
// sebagai private/loopback. Allowlist sengaja memuat entry numerik jahat
// (mensimulasikan salah konfigurasi operator) untuk membuktikan deny-first
// tetap berlaku dan tidak ada jalur "host match lalu connect".
func TestAdversarialScopeIPObfuscation(t *testing.T) {
	c := mustChecker(t, []string{
		"example.com",
		// Entry numerik jahat: sebelum hardening, URL dengan bentuk yang sama
		// lolos sebagai host match lalu connect ke loopback.
		"2130706433", "0x7f000001", "017700000001", "127.1", "127.0.1", "0177.0.0.1",
	})
	cases := []struct {
		name string
		url  string
		// parserRejects: ditolak url.Parse (ErrInvalidURL), bukan deny IP.
		parserRejects bool
	}{
		{"desimal penuh 127.0.0.1", "http://2130706433/", false},
		{"hex 127.0.0.1", "http://0x7f000001/", false},
		{"hex uppercase 127.0.0.1", "http://0X7F000001/", false},
		{"oktal 127.0.0.1", "http://017700000001/", false},
		{"hex campur 0x7f.1", "http://0x7f.1/", false},
		{"oktal campur 0177.0.0.1", "http://0177.0.0.1/", false},
		{"bentuk pendek 127.1", "http://127.1/", false},
		{"bentuk pendek 127.0.1", "http://127.0.1/", false},
		{"desimal + trailing dot", "http://2130706433./", false},
		{"desimal dengan port", "http://2130706433:80/", false},
		{"desimal 192.168.0.11", "http://3232235531/", false},
		{"IPv4-mapped IPv6 loopback", "http://[::ffff:127.0.0.1]/", false},
		// Bentuk ini ditolak url.Parse sendiri (ErrInvalidURL) — tetap ditolak,
		// tapi bukan lewat jalur deny IP.
		{"IPv4-mapped IPv6 desimal (parser tolak)", "http://[::ffff:2130706433]/", true},
		{"IPv6 loopback", "http://[::1]/", false},
		{"IPv6 loopback dengan zone", "http://[::1%25eth0]/", false},
		{"NAT64 well-known -> 127.0.0.1", "http://[64:ff9b::7f00:1]/", false},
		{"NAT64 -> metadata 169.254.169.254", "http://[64:ff9b::a9fe:a9fe]/", false},
		{"6to4 -> 10.0.0.1", "http://[2002:a00:1::]/", false},
	}
	for _, tc := range cases {
		err := c.Check(tc.url)
		if err == nil {
			t.Errorf("BYPASS: Check(%q) = nil — harus ditolak (%s)", tc.url, tc.name)
			continue
		}
		if tc.parserRejects {
			if !errors.Is(err, ErrInvalidURL) {
				t.Errorf("Check(%q) = %v, mau ErrInvalidURL (%s)", tc.url, err, tc.name)
			}
			continue
		}
		if !errors.Is(err, ErrPrivateAddress) && !errors.Is(err, ErrMetadataAddress) {
			t.Errorf("Check(%q) = %v, mau ditolak sebagai private/loopback/metadata (%s)", tc.url, err, tc.name)
		}
	}
}

// TestAdversarialScopeParserTricks: trik parser differential antara scope
// checker dan HTTP client. Aturan: apa pun yang tidak bisa dipastikan host-nya
// secara deterministik DITOLAK (fail-closed); kasus yang diizinkan hanya yang
// semantiknya identik dengan bentuk kanonik.
func TestAdversarialScopeParserTricks(t *testing.T) {
	c := mustChecker(t, []string{"example.com"})
	cases := []struct {
		name string
		url  string
		want error
	}{
		// Userinfo/backslash: parser memecah authority pada '@' terakhir —
		// host sebenarnya evil.tld, bukan example.com.
		{"backslash sebelum @ (authority confusion)", `http://example.com\@evil.tld/`, ErrInvalidURL},
		{"userinfo percent-encoded", `http://example.com%2f@evil.tld/`, ErrUserInfo},
		{"userinfo dengan port palsu", `http://example.com:80@evil.tld/`, ErrUserInfo},
		{"userinfo kosong", `http://@example.com/`, ErrUserInfo},
		{"backslash scheme (client lama treat sebagai //)", `http:/\/\evil.tld`, ErrInvalidURL},
		// Fragment bukan bagian dari authority: host tetap example.com
		// (fragment tidak pernah dikirim ke server) — bukan bypass, boleh.
		{"fragment vs host", `http://example.com#@evil.tld/`, nil},
		{"path double-slash", `http://example.com//evil`, nil},
		// Port: hanya default skema / yang terdaftar eksplisit.
		{"port tak terdaftar", `http://example.com:8043/`, ErrPortNotAllowed},
		{"port 0", `http://example.com:0/`, ErrPortNotAllowed},
		{"port overflow 65536", `http://example.com:65536/`, ErrPortNotAllowed},
		{"port raksasa", `http://example.com:99999999999/`, ErrPortNotAllowed},
		{"port nol-prefix (080 == 80, normalisasi deterministik)", `http://example.com:0080/`, nil},
		{"port kosong eksplisit", `http://example.com:/`, nil},
		// Normalisasi hostname.
		{"uppercase host", `http://EXAMPLE.COM/`, nil},
		{"trailing dot tunggal", `http://example.com./`, nil},
		{"trailing dot ganda", `http://example.com..//`, ErrHostNotAllowed},
		// Karakter berbahaya di host: Go url.Parse menolak sebagian besar;
		// yang lolos parse tetap tidak boleh match.
		{"spasi di host", `http://exa mple.com/`, ErrInvalidURL},
		{"null byte encoded", `http://example.com%00/`, ErrInvalidURL},
		{"newline encoded", `http://example.com%0a/`, ErrInvalidURL},
		{"backslash di host", `http://example.com\evil.tld/`, ErrInvalidURL},
		{"percent-encoded dot (host smuggling)", `http://example.com%2e%2e/`, ErrInvalidURL},
		{"percent-encoded slash di host", `http://example.com%2F/`, ErrInvalidURL},
		{"host unicode", `http://exämple.com/`, ErrInvalidURL},
	}
	for _, tc := range cases {
		err := c.Check(tc.url)
		if tc.want == nil {
			if err != nil {
				t.Errorf("Check(%q) = %v, mau diizinkan (%s)", tc.url, err, tc.name)
			}
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("Check(%q) = %v, mau %v (%s)", tc.url, err, tc.want, tc.name)
		}
	}
}

// TestAdversarialScopePunycodePolicy: stdlib Go tidak menyediakan IDNA/punycode
// encoder, jadi kebijakan deterministiknya: allowlist dan URL host WAJIB ASCII
// (operator menulis bentuk punycode "xn--..."). Entry unicode ditolak saat
// konstruksi, URL host unicode ditolak saat check — homoglyph tidak bisa
// menyamar sebagai entry unicode yang "mirip".
func TestAdversarialScopePunycodePolicy(t *testing.T) {
	// Entry unicode di allowlist = error fail-closed.
	for _, bad := range []string{"exämple.com", "xn--ä.com"} {
		if _, err := NewChecker([]string{bad}); err == nil {
			t.Errorf("NewChecker entry unicode %q harus error", bad)
		}
	}
	// Bentuk punycode ASCII sah dan boleh di-allowlist.
	c := mustChecker(t, []string{"xn--xmpl-3ua.com"})
	if err := c.Check("http://xn--xmpl-3ua.com/"); err != nil {
		t.Errorf("Check punycode = %v, mau diizinkan", err)
	}
	// Homoglyph unicode tidak bisa match entry punycode (ditolak fail-closed).
	if err := c.Check("http://exämple.com/"); err == nil {
		t.Error("host unicode harus ditolak meski allowlist berisi punycode")
	}
}

// TestAdversarialScopeWildcardAbuse: wildcard hanya SATU level, tidak boleh
// global, tidak boleh kosong, tidak boleh lewat substring.
func TestAdversarialScopeWildcardAbuse(t *testing.T) {
	c := mustChecker(t, []string{"*.example.com"})
	deny := []string{
		"https://a.b.example.com/", // dua level
		"https://anexample.com/",   // substring apex
		"https://example.com/",     // apex tidak dicakup
		"https://*.example.com/",   // label '*' literal di host
		"https://a.example.com.attacker.tld/",
	}
	for _, u := range deny {
		if err := c.Check(u); err == nil {
			t.Errorf("BYPASS: Check(%q) = nil, harus ditolak", u)
		}
	}
	// Kasus izin sah (satu level; case/trailing dot dinormalisasi):
	allow := []string{"https://foo.example.com/", "https://FOO.EXAMPLE.COM./"}
	for _, u := range allow {
		if err := c.Check(u); err != nil {
			t.Errorf("Check(%q) = %v, mau diizinkan", u, err)
		}
	}
	// Entry wildcard global/kosong/aneh ditolak saat konstruksi
	// (wildcard "*" global = allow-all bypass).
	for _, bad := range []string{"*", "**", "*.", "*.*", "*.example.*", "x*", "*x", "a.*.b"} {
		if _, err := NewChecker([]string{bad}); err == nil {
			t.Errorf("NewChecker wildcard %q harus error", bad)
		}
	}
}

// TestAdversarialScopeAllowlistHardening: entry allowlist malformed harus
// ditolak saat konstruksi, bukan saat eksekusi.
func TestAdversarialScopeAllowlistHardening(t *testing.T) {
	for _, bad := range []string{
		"example.com:0",     // port 0 tidak valid
		"example.com:65536", // port overflow
		"example.com:abc",   // port bukan angka
		"a..example.com",    // label kosong
		".example.com",      // mulai dengan dot
		"example.com...",    // hanya SATU trailing dot yang dinormalisasi
	} {
		if _, err := NewChecker([]string{bad}); err == nil {
			t.Errorf("NewChecker entry %q harus error", bad)
		}
	}
	// Port entry dinormalisasi: ":080" == ":80" (deterministik).
	c, err := NewChecker([]string{"example.com:080"})
	if err != nil {
		t.Fatalf("NewChecker(example.com:080) error: %v", err)
	}
	if err := c.Check("http://example.com:080/"); err != nil {
		t.Errorf("port 080 harus sama dengan 80: %v", err)
	}
	if err := c.Check("http://example.com:80/"); err != nil {
		t.Errorf("port 80 harus cocok entry :080 ternormalisasi: %v", err)
	}
}

// TestAdversarialScopePublicNumericCanonical: bentuk numerik IP PUBLIK harus
// diperlakukan sebagai IP literal yang sama dengan bentuk dotted-quad-nya —
// matching kanonik, bukan string-match mentokan teks mentah.
func TestAdversarialScopePublicNumericCanonical(t *testing.T) {
	c := mustChecker(t, []string{"8.8.8.8"})
	// 134744072 == 0x08080808 == 8.8.8.8 (publik: tidak ditolak keras, tapi
	// hanya lewat bila allowlist memuat IP yang sama secara kanonik).
	if err := c.Check("http://134744072/"); err != nil {
		t.Errorf("Check(134744072) = %v, mau diizinkan (canonical 8.8.8.8)", err)
	}
	if err := c.Check("http://0x08080808/"); err != nil {
		t.Errorf("Check(0x08080808) = %v, mau diizinkan (canonical 8.8.8.8)", err)
	}
	// IP publik lain tetap ditolak.
	if err := c.Check("http://134744073/"); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("Check(134744073) = %v, mau ErrHostNotAllowed", err)
	}
}
