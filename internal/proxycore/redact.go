package proxycore

import (
	"net/http"
	"strings"
)

// RedactedValue adalah pengganti nilai header sensitif sebelum data keluar
// dari proxy menuju reasoning context (ROADMAP §24/§25, Phase 7.7).
const RedactedValue = "[REDACTED]"

// validHeaderFieldName melaporkan apakah name adalah field-name HTTP sah per
// RFC 7230 (token: ALPHA / DIGIT / "!#$%&'*+-.^_`|~"). Nama yang mengandung
// spasi, tab, newline, colon, dsb. TIDAK sah.
func validHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validHeaderFieldValue melaporkan apakah value sah sebagai field-value HTTP
// (VCHAR / obs-text / SP / HTAB — byte kontrol lainnya ditolak).
func validHeaderFieldValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// isSensitiveHeader melaporkan apakah sebuah nama header wajib diredaksi.
//
// Aturan (§24/§25):
//   - nama header TIDAK VALID (spasi "X Y", tab, newline, dsb.) dianggap
//     sensitif — fail-closed. Nama seperti itu adalah vektor header
//     smuggling/parser differential: komponen yang memvalidasi dan yang
//     tidak bisa membedah "X Y: z" secara berbeda, jadi tidak boleh keluar
//     dari proxy tanpa redaksi;
//   - Authorization, Cookie, Set-Cookie, X-Api-Key, dan header yang namanya
//     mengandung token/key/secret/auth/password/credential/session/jwt/bearer
//     (case-insensitive). Aturan substring sengaja over-redaksi: salah
//     meredaksi header jinak aman; melewatkan header sensitif tidak.
//     Daftar eksplisit dipertahankan agar intent-nya terbaca saat audit.
func isSensitiveHeader(name string) bool {
	if !validHeaderFieldName(name) {
		return true
	}
	n := strings.ToLower(name)
	for _, s := range []string{"token", "key", "secret", "auth", "password", "passwd", "credential", "session", "jwt", "bearer"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	switch n {
	case "authorization", "cookie", "set-cookie", "proxy-authorization", "www-authenticate":
		return true
	}
	return false
}

// RedactHeaders mengembalikan salinan header dengan nilai header sensitif
// diganti "[REDACTED]". WAJIB dipanggil pada semua header (request maupun
// response) sebelum masuk respons API atau evidence — header mentah tidak
// boleh keluar dari proxy (§24/§25, §23 sanitasi otomatis).
func RedactHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for name, vals := range h {
		if isSensitiveHeader(name) {
			out[name] = []string{RedactedValue}
			continue
		}
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[name] = cp
	}
	return out
}
