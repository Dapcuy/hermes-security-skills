package proxycore

import (
	"net/http"
	"strings"
)

// RedactedValue adalah pengganti nilai header sensitif sebelum data keluar
// dari proxy menuju reasoning context (ROADMAP §24/§25, Phase 7.7).
const RedactedValue = "[REDACTED]"

// isSensitiveHeader melaporkan apakah sebuah nama header wajib diredaksi.
//
// Aturan (§24/§25): Authorization, Cookie, Set-Cookie, X-Api-Key, dan header
// yang namanya mengandung token/key/secret. Aturan substring (case-insensitive)
// sudah mencakup keempat nama eksplisit itu ("authorization", "cookie", "key"),
// tetapi daftar eksplisit dipertahankan agar intent-nya terbaca saat audit.
func isSensitiveHeader(name string) bool {
	n := strings.ToLower(name)
	if strings.Contains(n, "token") || strings.Contains(n, "key") || strings.Contains(n, "secret") {
		return true
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
