package proxycore

import (
	"net/http"
	"testing"
)

func TestRedactHeaders(t *testing.T) {
	in := http.Header{
		"Authorization":       {"Bearer rahasia"},
		"Cookie":              {"session=abc"},
		"Set-Cookie":          {"sid=xyz; HttpOnly"},
		"X-Api-Key":           {"key-123"},
		"X-Session-Token":     {"tok-456"},
		"Client-Secret":       {"sec-789"},
		"Proxy-Authorization": {"Basic abc"},
		"Content-Type":        {"application/json"},
		"Cache-Control":       {"no-cache"},
		"Accept-Encoding":     {"gzip"},
	}
	out := RedactHeaders(in)
	for _, name := range []string{"Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Session-Token", "Client-Secret", "Proxy-Authorization"} {
		got := out.Get(name)
		if got != RedactedValue {
			t.Errorf("header %q = %q, mau %q", name, got, RedactedValue)
		}
	}
	if out.Get("Content-Type") != "application/json" {
		t.Error("header non-sensitif tidak boleh berubah")
	}
	if out.Get("Cache-Control") != "no-cache" || out.Get("Accept-Encoding") != "gzip" {
		t.Error("header non-sensitif lain berubah")
	}
	// Header asli tidak boleh ikut berubah (salinan, bukan mutasi).
	if in.Get("Authorization") != "Bearer rahasia" {
		t.Error("header asli harus tetap utuh (RedactHeaders bekerja pada salinan)")
	}
}

func TestIsSensitiveHeader(t *testing.T) {
	positif := []string{"Authorization", "authorization", "COOKIE", "Set-Cookie", "X-Api-Key", "X-Auth-Token", "Api-Key", "Signing-Secret", "X-Csrf-Token", "Proxy-Authorization"}
	for _, n := range positif {
		if !isSensitiveHeader(n) {
			t.Errorf("%q harus dianggap sensitif", n)
		}
	}
	negatif := []string{"Content-Type", "Accept", "Location", "Cache-Control", "X-Request-Id", "Server"}
	for _, n := range negatif {
		if isSensitiveHeader(n) {
			t.Errorf("%q TIDAK boleh dianggap sensitif", n)
		}
	}
}

// TestAdversarialHeaderSmugglingRedaction: semua varian nama header — casing
// campur, substring token/key/secret, dan NAMA TIDAK VALID (spasi, tab,
// newline, colon, kosong = vektor header smuggling) — HARUS ter-redaksi.
// Nama tidak valid dianggap sensitif secara fail-closed karena komponen yang
// berbeda bisa membedah "X Y: z" secara berbeda (parser differential).
func TestAdversarialHeaderSmugglingRedaction(t *testing.T) {
	in := http.Header{
		"aUtHoRiZaTiOn": {"Bearer varian-casing"},
		"X-API-KEY":     {"key-varian"},
		"private-token": {"token-varian"},
		"X-Session-Id":  {"sess-123"},
		"X-Jwt":         {"jwt-123"},
		"X-Auth-Data":   {"auth-123"},
		"X-Password":    {"pw-123"},
		// Header smuggling: nama bukan RFC 7230 token.
		"X Y":            {"smuggling-spasi"},
		"Authorization ": {"spasi-ekor"},
		"X\tTab":         {"tab"},
		"X\nY":           {"newline"},
		"X:Colon":        {"colon"},
		"":               {"nama kosong"},
		// Kontrol: header jinak tidak boleh ikut diredaksi.
		"Cache-Control": {"no-cache"},
	}
	out := RedactHeaders(in)
	mustRedact := []string{
		"aUtHoRiZaTiOn", "X-API-KEY", "private-token", "X-Session-Id", "X-Jwt",
		"X-Auth-Data", "X-Password",
		"X Y", "Authorization ", "X\tTab", "X\nY", "X:Colon", "",
	}
	for _, name := range mustRedact {
		vals, ok := out[name]
		if !ok || len(vals) != 1 || vals[0] != RedactedValue {
			t.Errorf("BYPASS: header %q tidak ter-redaksi: %v", name, vals)
		}
	}
	if out.Get("Cache-Control") != "no-cache" {
		t.Error("header jinak tidak boleh berubah")
	}
	// Header asli tetap utuh (RedactHeaders bekerja pada salinan); akses map
	// langsung karena Get() mengkanonikalisasi nama.
	if vals := in["aUtHoRiZaTiOn"]; len(vals) != 1 || vals[0] != "Bearer varian-casing" {
		t.Error("header asli harus tetap utuh")
	}
}

// TestAdversarialHeaderNameValidityUnits: kontrak validHeaderFieldName /
// validHeaderFieldValue yang dipakai engine untuk menolak input 400.
func TestAdversarialHeaderNameValidityUnits(t *testing.T) {
	invalidNames := []string{"", "X Y", "Authorization ", "X\tTab", "X\nY", "X:Colon", "X\rY", "X(Y)", "héader"}
	for _, n := range invalidNames {
		if validHeaderFieldName(n) {
			t.Errorf("validHeaderFieldName(%q) = true, mau false", n)
		}
	}
	validNames := []string{"Authorization", "X-API-KEY", "private-token", "X_Custom", "X-A.B", "h1", "X#Y"}
	for _, n := range validNames {
		if !validHeaderFieldName(n) {
			t.Errorf("validHeaderFieldName(%q) = false, mau true", n)
		}
	}
	invalidValues := []string{"a\r\nX-Injected: 1", "bad\nvalue", "\x00", "\x7f", "a\rb"}
	for _, v := range invalidValues {
		if validHeaderFieldValue(v) {
			t.Errorf("validHeaderFieldValue(%q) = true, mau false", v)
		}
	}
	validValues := []string{"", "text/plain", "a b\tc", "Bearer xyz; charset=utf-8"}
	for _, v := range validValues {
		if !validHeaderFieldValue(v) {
			t.Errorf("validHeaderFieldValue(%q) = false, mau true", v)
		}
	}
}
