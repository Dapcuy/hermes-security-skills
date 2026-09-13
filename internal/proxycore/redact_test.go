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
