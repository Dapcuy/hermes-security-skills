// Package scope mengimplementasikan scope matcher (ROADMAP 8 — Scope).
//
// Aturan (fail-closed, parser-based BUKAN substring matching):
//   - hanya skema http/https
//   - URL dengan userinfo ditolak
//   - hostname dicocokkan exact per-label (lowercase, trailing dot dinormalisasi)
//   - wildcard '*.example.com' hanya cocok SATU level subdomain
//     (bukan apex, bukan dua level, dan bukan host yang label pertamanya
//     literal '*' — host '*.example.com' adalah nama DNS berbeda yang bisa
//     di-resolve via wildcard record, jadi TIDAK boleh match)
//   - entry allowlist boleh memuat port ("host:443"); entry tanpa port hanya
//     cocok dengan port default skema (80/443) — port non-default harus
//     eksplisit di allowlist; port dibandingkan setelah normalisasi numerik
//     (":080" == ":80") dan di luar 1..65535 ditolak
//   - host non-ASCII ditolak (kebijakan punycode: stdlib Go tidak menyediakan
//     IDNA, jadi allowlist dan URL wajib bentuk ASCII/punycode "xn--...")
//   - IP literal privat (RFC1918), loopback, link-local, unspecified, CGNAT,
//     dan cloud metadata 169.254.169.254 DITOLAK keras, walau ada di allowlist.
//     "IP literal" di sini mencakup SEMUA representasi numerik yang diterima
//     resolver OS (semantik inet_aton): desimal penuh "2130706433", hex
//     "0x7f000001", oktal "017700000001", bentuk pendek "127.1"/"127.0.1",
//     campuran per-bagian "0x7f.1"/"0177.0.0.1", IPv6 dengan zone
//     "[::1%25eth0]", serta alamat transisi IPv6 yang membawa IPv4 ter-embed
//     (IPv4-mapped ::ffff:0/96, NAT64 64:ff9b::/96, 6to4 2002::/16)
//   - host di luar allowlist ditolak
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
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
// Entry invalid (kosong, karakter aneh, wildcard ganda, label kosong,
// non-ASCII, port di luar 1..65535) = error fail-closed.
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
		// SplitHostPort berhasil: entry dengan port eksplisit. Port "host:"
		// (kosong) dan port di luar 1..65535 ditolak; port dinormalisasi
		// numerik agar ":080" dan ":80" identik (deterministik, tidak bisa
		// dipakai menyelundupkan port lewat nol-prefix).
		if port == "" {
			return e, fmt.Errorf("scope: entry allowlist %q tanpa port", raw)
		}
		pn, perr := strconv.Atoi(port)
		if perr != nil || pn < 1 || pn > 65535 {
			return e, fmt.Errorf("scope: entry allowlist %q port tidak valid", raw)
		}
		e.port = strconv.Itoa(pn)
		e.host = strings.TrimSuffix(strings.ToLower(host), ".")
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
	if !isASCII(e.host) {
		// Kebijakan punycode (lihat komentar package): tanpa IDNA stdlib,
		// entry non-ASCII tidak bisa dicocokkan deterministik — ditolak.
		return e, fmt.Errorf("scope: entry allowlist %q non-ASCII — gunakan bentuk punycode (xn--...)", raw)
	}
	// Entry IP literal dinormalisasi ke bentuk kanonik (juga menangkap bentuk
	// numerik inet_aton seperti "2130706433"/"0x7f000001") agar matching
	// URL numerik vs entry dotted-quad konsisten. Deny-private tetap terjadi
	// di Check (deny-first), bukan di sini.
	if ip := parseIPLiteral(e.host); ip != nil {
		e.host = ip.String()
	} else {
		// Hostname: semua label wajib non-kosong ("a..b", ".b", "a.." ditolak).
		for _, lbl := range strings.Split(e.host, ".") {
			if lbl == "" {
				return e, fmt.Errorf("scope: entry allowlist %q punya label kosong", raw)
			}
		}
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

// isASCII melaporkan apakah s hanya berisi byte ASCII.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
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
	if !isASCII(host) {
		// Kebijakan punycode (lihat komentar package): host unicode tidak bisa
		// dicocokkan deterministik dengan allowlist ASCII — ditolak fail-closed
		// (homoglyph/punycode smuggling tertutup).
		return fmt.Errorf("%w: host %q non-ASCII — gunakan bentuk punycode (xn--...)", ErrInvalidURL, host)
	}
	port := u.Port()
	if port == "" {
		port = defaultPort(u.Scheme)
	} else {
		// Normalisasi numerik: "080" == "80", dan port di luar 1..65535
		// (termasuk 0 dan overflow) ditolak — fail-closed.
		pn, perr := strconv.Atoi(port)
		if perr != nil || pn < 1 || pn > 65535 {
			return fmt.Errorf("%w: %q tidak valid", ErrPortNotAllowed, port)
		}
		port = strconv.Itoa(pn)
	}
	if port == "" {
		return fmt.Errorf("%w: port tidak diketahui untuk skema %q", ErrPortNotAllowed, u.Scheme)
	}

	// IP literal: cek keamanan dulu (deny keras), lalu harus match exact.
	// parseIPLiteral menormalkan SEMUA representasi numerik (dotted-quad,
	// inet_aton desimal/hex/oktal/pendek, IPv6 + zone) — host yang terlihat
	// seperti "2130706433" atau "127.1" TIDAK boleh diperlakukan sebagai
	// hostname biasa: resolver OS akan menghubungkannya ke 127.0.0.1.
	isIP := false
	if ip := parseIPLiteral(host); ip != nil {
		isIP = true
		host = ip.String() // bentuk kanonik untuk matching allowlist
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

// parseIPLiteral menormalkan host menjadi net.IP bila host adalah literal IP
// dalam representasi APA PUN yang diterima resolver OS:
//   - dotted-quad IPv4 / bentuk apapun yang diterima net/netip (IPv6, zone
//     index seperti "::1%eth0", IPv4-mapped);
//   - semantik inet_aton: 1-4 bagian dipisah titik, bagian terakhir mengisi
//     sisa bit; tiap bagian boleh desimal, hex "0x...", atau oktal "0..."
//     ("2130706433" = 0x7f000001 = 017700000001 = "127.1" = 127.0.0.1).
//
// Return nil bila host bukan literal IP (hostname biasa). Parser ini WAJIB
// dipakai sebelum mencocokkan allowlist: kalau tidak, representasi numerik
// loopback/privat lolos sebagai "hostname tidak dikenal" dan tetap di-dial.
func parseIPLiteral(host string) net.IP {
	// netip.ParseAddr lebih ketat dan lengkap dari net.ParseIP: menolak
	// oktal/leading-zero, tapi menerima IPv6 zone ("fe80::1%eth0") yang
	// juga bisa di-dial. Bila bukan literal netip, coba semantik inet_aton.
	if a, err := netip.ParseAddr(host); err == nil {
		return addrToNetIP(a)
	}
	return parseIPv4Numeric(host)
}

// addrToNetIP mengonversi netip.Addr ke net.IP (mempertahankan bentuk
// 4-byte untuk IPv4 dan IPv4-mapped agar To4()/IsDeniedIP bekerja).
func addrToNetIP(a netip.Addr) net.IP {
	if a.Is4() || a.Is4In6() {
		b4 := a.As4()
		return net.IPv4(b4[0], b4[1], b4[2], b4[3])
	}
	b16 := a.As16()
	return net.IP(b16[:])
}

// parseIPv4Numeric mem-parse host dengan semantik inet_aton: 1-4 bagian,
// bagian terakhir menempati sisa byte (a = a.0.0.0; a.b = a.(b 24-bit);
// dst). Tiap bagian boleh desimal, hex (0x), atau oktal (leading 0).
// Return nil bila bukan representasi numerik yang valid.
func parseIPv4Numeric(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) > 4 || len(parts) < 1 {
		return nil
	}
	var v uint64
	last := len(parts) - 1
	for i, p := range parts {
		n, ok := parseHostNumber(p)
		if !ok {
			return nil
		}
		if i < last {
			// Bagian non-terakhir: tepat satu oktet.
			if n > 0xFF {
				return nil
			}
			v = v<<8 | n
			continue
		}
		// Bagian terakhir mengisi sisa byte: 1 bagian = 32 bit, 2 bagian =
		// 24 bit untuk bagian terakhir, dst.
		bits := uint(8 * (4 - last))
		if bits == 0 || n >= 1<<bits {
			return nil
		}
		v = v<<bits | n
	}
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}

// parseHostNumber mem-parse satu bagian angka host inet_aton: desimal,
// hex "0x...", atau oktal bila diawali '0' (dua digit atau lebih).
func parseHostNumber(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := uint64(10)
	digits := "0123456789"
	if len(p) > 2 && (p[0] == '0') && (p[1] == 'x' || p[1] == 'X') {
		base = 16
		digits = "0123456789abcdef"
		p = p[2:]
	} else if len(p) > 1 && p[0] == '0' {
		base = 8
		digits = "01234567"
		p = p[1:]
	}
	if len(p) == 0 || len(p) > 16 {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(p); i++ {
		idx := strings.IndexByte(digits, lowerByte(p[i]))
		if idx < 0 {
			return 0, false
		}
		n = n*base + uint64(idx)
		if n > 0xFFFFFFFF { // clamp: bukan IPv4 yang sah
			return 0, false
		}
	}
	return n, true
}

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// matchWildcard: pattern "*.<rest>" cocok hanya jika host punya jumlah label
// sama, label pertama host TEPAT SATU label non-kosong, dan label pertama
// itu BUKAN wildcard literal. Kasus tercakup:
//   - "example.com" != "*.example.com" (apex tidak cocok)
//   - "a.b.example.com" != "*.example.com" (dua level tidak cocok)
//   - "evil-example.com" != "*.example.com" (label dicocokkan exact)
//   - "*.example.com" != "*.example.com" (host ber-wildcard literal adalah
//     nama DNS berbeda — wildcard record bisa meng-resolve-nya ke IP siapa
//     pun — jadi TIDAK boleh match pattern wildcard; advesari bisa mendaftar
//     "*.<zona>" dan menerima koneksi proxy)
func matchWildcard(pattern, host string) bool {
	pp := strings.Split(pattern, ".")
	hp := strings.Split(host, ".")
	if len(pp) != len(hp) {
		return false
	}
	if pp[0] != "*" {
		return false
	}
	if hp[0] == "" || strings.Contains(hp[0], "*") {
		return false // label kosong (double dot) atau wildcard literal di host
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
// unique-local v6, dan semua alamat transisi yang membawa IPv4 ter-embed
// (IPv4-mapped ::ffff:0/96, NAT64 64:ff9b::/96, 6to4 2002::/16) bila IPv4
// yang di-embed termasuk kategori terlarang — mencegah SSRF lewat gateway
// transisi yang memetakan alamat IPv6 itu ke IPv4 privat/loopback.
func IsDeniedIP(ip net.IP) bool {
	if ip == nil {
		return true // fail-closed
	}
	if v4 := transitionIPv4(ip); v4 != nil {
		return isDeniedIPv4(v4)
	}
	// IPv6 murni.
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// isDeniedIPv4 mengevaluasi kategori terlarang untuk IPv4 murni.
func isDeniedIPv4(t4 net.IP) bool {
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

// transitionIPv4 mengembalikan IPv4 yang ter-embed pada alamat transisi:
// IPv4-mapped (::ffff:0:0/96, termasuk hasil To4()), NAT64 well-known prefix
// 64:ff9b::/96 (4 byte terakhir), atau 6to4 2002::/16 (byte 3-6).
// Return nil bila bukan alamat transisi.
func transitionIPv4(ip net.IP) net.IP {
	if t4 := ip.To4(); t4 != nil {
		return t4 // IPv4 murni dan IPv4-mapped
	}
	if len(ip) != 16 {
		return nil
	}
	// 64:ff9b::/96: 00 64 ff 9b + 8 byte nol + 4 byte IPv4.
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		allZero(ip[4:12]) {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	// 2002::/16 (6to4): byte 2..5 = IPv4 target.
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()
	}
	return nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// IsCloudMetadata menandai endpoint metadata cloud provider.
func IsCloudMetadata(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := transitionIPv4(ip); v4 != nil {
		// AWS/GCP/Azure metadata service (link-local), termasuk lewat
		// alamat transisi (mis. NAT64 -> 169.254.169.254).
		return v4[0] == 169 && v4[1] == 254 && v4[2] == 169 && v4[3] == 254
	}
	// AWS IMDS IPv6.
	return ip.Equal(net.ParseIP("fd00:ec2::254"))
}
