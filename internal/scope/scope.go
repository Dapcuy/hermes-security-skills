// Package scope mengimplementasikan scope matcher (ROADMAP 8 — Scope).
//
// Aturan (fail-closed, parser-based BUKAN substring matching):
//   - hanya skema http/https
//   - URL dengan userinfo ditolak
//   - hostname dicocokkan exact per-label (lowercase, trailing dot dinormalisasi)
//   - wildcard '*.example.com' hanya cocok SATU level subdomain
//     (bukan apex, bukan dua level)
//   - entry allowlist boleh memuat port ("host:443"); entry tanpa port hanya
//     cocok dengan port default skema (80/443) — port non-default harus
//     eksplisit di allowlist
//   - IP literal privat (RFC1918), loopback, link-local, unspecified, CGNAT,
//     dan cloud metadata 169.254.169.254 DITOLAK keras, walau ada di allowlist
//   - host di luar allowlist ditolak
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	ErrInvalidURL        = errors.New("scope: URL tidak valid")
	ErrUnsupportedScheme = errors.New("scope: skema tidak didukung")
	ErrUserInfo          = errors.New("scope: URL mengandung userinfo")
	ErrPrivateAddress    = errors.New("scope: alamat IP privat/loopback/link-local dilarang")
	ErrMetadataAddress   = errors.New("scope: cloud metadata endpoint dilarang")
	ErrHostNotAllowed    = errors.New("scope: host di luar scope")
	ErrPortNotAllowed    = errors.New("scope: port tidak di-allowlist")
)

type hostPort struct {
	host string
	port string // "" = hanya port default skema yang diizinkan
	wild bool   // pattern "*.example.com"
}

// Checker menyimpan allowlist hasil normalisasi dan aman dipakai ulang.
type Checker struct {
	allowed []hostPort
}

// NewChecker membangun Checker dari daftar entry allowlist.
// Entry invalid (kosong, karakter aneh, wildcard ganda) = error fail-closed.
func NewChecker(allowed []string) (*Checker, error) {
	c := &Checker{}
	for _, raw := range allowed {
		e, err := parseEntry(raw)
		if err != nil {
			return nil, err
		}
		c.allowed = append(c.allowed, e)
	}
	return c, nil
}

func parseEntry(raw string) (hostPort, error) {
	e := hostPort{}
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return e, fmt.Errorf("scope: entry allowlist kosong")
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if port == "" {
			return e, fmt.Errorf("scope: entry allowlist %q tanpa port", raw)
		}
		if !allDigits(port) {
			return e, fmt.Errorf("scope: entry allowlist %q port tidak valid", raw)
		}
		e.host = strings.TrimSuffix(strings.ToLower(host), ".")
		e.port = port
	} else {
		// Tanpa port; SplitHostPort bisa gagal untuk host biasa.
		e.host = strings.TrimSuffix(s, ".")
	}
	if e.host == "" {
		return e, fmt.Errorf("scope: entry allowlist %q tanpa host", raw)
	}
	if strings.ContainsAny(e.host, " /\\@?") {
		return e, fmt.Errorf("scope: entry allowlist %q mengandung karakter tidak valid", raw)
	}
	if strings.HasPrefix(e.host, "*.") {
		rest := strings.TrimPrefix(e.host, "*.")
		if strings.Contains(rest, "*") || rest == "" {
			return e, fmt.Errorf("scope: wildcard %q tidak valid (hanya satu '*.' di depan)", raw)
		}
		e.wild = true
	} else if strings.Contains(e.host, "*") {
		return e, fmt.Errorf("scope: wildcard %q hanya boleh sebagai label pertama '*.'", raw)
	}
	return e, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Check memvalidasi rawURL terhadap allowlist. Nil = diizinkan.
func (c *Checker) Check(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: %q", ErrUnsupportedScheme, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %q", ErrUserInfo, u.Redacted())
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return fmt.Errorf("%w: host kosong", ErrInvalidURL)
	}
	port := u.Port()
	if port == "" {
		port = defaultPort(u.Scheme)
	}
	if port == "" {
		return fmt.Errorf("%w: port tidak diketahui untuk skema %q", ErrPortNotAllowed, u.Scheme)
	}

	// IP literal: cek keamanan dulu (deny keras), lalu harus match exact.
	isIP := false
	if ip := net.ParseIP(host); ip != nil {
		isIP = true
		if IsCloudMetadata(ip) {
			return fmt.Errorf("%w: %s", ErrMetadataAddress, host)
		}
		if IsDeniedIP(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateAddress, host)
		}
	}

	hostMatched := false
	for _, e := range c.allowed {
		if e.wild {
			if isIP || !matchWildcard(e.host, host) {
				continue
			}
		} else if e.host != host {
			continue
		}
		// Host cocok; periksa port.
		hostMatched = true
		if e.port == "" {
			if port != defaultPort(u.Scheme) {
				continue
			}
			return nil
		}
		if e.port == port {
			return nil
		}
	}
	if hostMatched {
		return fmt.Errorf("%w: %s:%s", ErrPortNotAllowed, host, port)
	}
	return fmt.Errorf("%w: %s", ErrHostNotAllowed, host)
}

// Validate adalah convenience wrapper: bangun Checker lalu Check satu URL.
func Validate(rawURL string, allowedHosts []string) error {
	c, err := NewChecker(allowedHosts)
	if err != nil {
		return err
	}
	return c.Check(rawURL)
}

func defaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// matchWildcard: pattern "*.<rest>" cocok hanya jika host punya jumlah label
// sama dan label pertama host adalah tepat SATU label non-kosong.
// Kasus tercakup: "example.com" != "*.example.com" (apex tidak cocok),
// "a.b.example.com" != "*.example.com" (dua level tidak cocok),
// "evil-example.com" != "*.example.com" (label dicocokkan exact).
func matchWildcard(pattern, host string) bool {
	pp := strings.Split(pattern, ".")
	hp := strings.Split(host, ".")
	if len(pp) != len(hp) {
		return false
	}
	if pp[0] != "*" {
		return false
	}
	if hp[0] == "" {
		return false // label kosong (double dot)
	}
	for i := 1; i < len(pp); i++ {
		if pp[i] != hp[i] {
			return false
		}
	}
	return true
}

// IsDeniedIP melaporkan apakah IP termasuk kategori yang SELALU ditolak:
// RFC1918, loopback, link-local (v4/v6), unspecified, CGNAT 100.64/10,
// unique-local v6, dan IPv4-mapped IPv6 yang tujuannya privat.
func IsDeniedIP(ip net.IP) bool {
	if ip == nil {
		return true // fail-closed
	}
	if t4 := ip.To4(); t4 != nil {
		switch {
		case t4[0] == 0: // 0.0.0.0/8 (unspecified / "this network")
			return true
		case t4[0] == 10: // 10.0.0.0/8 RFC1918
			return true
		case t4[0] == 127: // 127.0.0.0/8 loopback
			return true
		case t4[0] == 169 && t4[1] == 254: // 169.254.0.0/16 link-local
			return true
		case t4[0] == 172 && t4[1] >= 16 && t4[1] <= 31: // 172.16.0.0/12 RFC1918
			return true
		case t4[0] == 192 && t4[1] == 168: // 192.168.0.0/16 RFC1918
			return true
		case t4[0] == 100 && t4[1] >= 64 && t4[1] <= 127: // 100.64.0.0/10 CGNAT
			return true
		}
		return false
	}
	// IPv6 murni.
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// IsCloudMetadata menandai endpoint metadata cloud provider.
func IsCloudMetadata(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if t4 := ip.To4(); t4 != nil {
		// AWS/GCP/Azure metadata service (link-local).
		return t4[0] == 169 && t4[1] == 254 && t4[2] == 169 && t4[3] == 254
	}
	// AWS IMDS IPv6.
	return ip.Equal(net.ParseIP("fd00:ec2::254"))
}
