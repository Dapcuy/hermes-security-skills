package proxycore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceStoreWriteAndIntegrity(t *testing.T) {
	dir := t.TempDir()
	es, err := NewEvidenceStore(dir)
	if err != nil {
		t.Fatalf("NewEvidenceStore: %v", err)
	}
	rec := EvidenceRecord{
		Request: EvidenceRequest{
			Method:       "GET",
			URL:          "https://api.example.com/x",
			Headers:      RedactHeaders(http.Header{"Authorization": {"Bearer x"}}),
			BodyBase64:   "",
			BodyEncoding: "base64",
		},
		Response: EvidenceResponse{
			Status:       200,
			Headers:      RedactHeaders(http.Header{"Set-Cookie": {"a=b"}}),
			BodyBase64:   "aGVsbG8=",
			BodyEncoding: "base64",
		},
	}
	ref, shaHex, err := es.Write(rec)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if ref != "evidence-000001.json" {
		t.Errorf("ref = %q, mau evidence-000001.json", ref)
	}

	data, err := os.ReadFile(filepath.Join(dir, ref))
	if err != nil {
		t.Fatalf("baca evidence: %v", err)
	}
	var ef evidenceFile
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	// Verifikasi sha256 atas konten tanpa field sha256 (§25 Evidence Integrity).
	core, err := json.Marshal(ef.EvidenceRecord)
	if err != nil {
		t.Fatalf("marshal ulang: %v", err)
	}
	sum := sha256.Sum256(core)
	if hex.EncodeToString(sum[:]) != ef.SHA256 {
		t.Errorf("sha256 evidence tidak cocok (got %s, recorded %s)", hex.EncodeToString(sum[:]), ef.SHA256)
	}
	if ef.SHA256 != shaHex {
		t.Errorf("return sha != file sha (%s vs %s)", shaHex, ef.SHA256)
	}
	if ef.Provenance["component"] != "hermes-proxy" {
		t.Errorf("provenance component = %q, mau hermes-proxy", ef.Provenance["component"])
	}
	if ef.CapturedAt == "" {
		t.Error("captured_at wajib terisi")
	}
	// Header sensitif di evidence wajib diredaksi.
	if ef.Request.Headers.Get("Authorization") != RedactedValue {
		t.Errorf("evidence request Authorization = %q, mau %q", ef.Request.Headers.Get("Authorization"), RedactedValue)
	}
	if ef.Response.Headers.Get("Set-Cookie") != RedactedValue {
		t.Errorf("evidence response Set-Cookie = %q, mau %q", ef.Response.Headers.Get("Set-Cookie"), RedactedValue)
	}

	// Seq berurutan.
	ref2, _, err := es.Write(rec)
	if err != nil {
		t.Fatalf("Write kedua: %v", err)
	}
	if ref2 != "evidence-000002.json" {
		t.Errorf("ref kedua = %q, mau evidence-000002.json", ref2)
	}
}

func TestNewEvidenceStoreCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "evidence")
	es, err := NewEvidenceStore(dir)
	if err != nil {
		t.Fatalf("NewEvidenceStore: %v", err)
	}
	if es.Dir() != dir {
		t.Errorf("Dir = %q, mau %q", es.Dir(), dir)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Error("direktori evidence harus dibuat")
	}
}

// verifyEvidence mereplikasi kontrak consumer sha256 (internal/events
// parseAndVerify — wilayah package lain, jadi kontraknya dicerminkan persis):
// sha256 dihitung ulang atas konten core (tanpa field sha256) dan dibandingkan
// dengan sha256 yang tercatat.
func verifyEvidence(data []byte) bool {
	var ef evidenceFile
	if err := json.Unmarshal(data, &ef); err != nil {
		return false
	}
	if strings.TrimSpace(ef.SHA256) == "" {
		return false
	}
	core, err := json.Marshal(ef.EvidenceRecord)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(core)
	return strings.EqualFold(hex.EncodeToString(sum[:]), ef.SHA256)
}

// TestAdversarialEvidenceTamperDetection: satu byte pun yang diubah pada file
// evidence — isi, urutan, atau sha256 itu sendiri — HARUS membuat verifikasi
// sha256 consumer gagal (§25 Evidence Integrity).
func TestAdversarialEvidenceTamperDetection(t *testing.T) {
	dir := t.TempDir()
	es, err := NewEvidenceStore(dir)
	if err != nil {
		t.Fatalf("NewEvidenceStore: %v", err)
	}
	const bodyText = "halo-evidence-tamper"
	const bodyB64 = "aGFsby1ldmlkZW5jZS10YW1wZXI=" // base64(bodyText)
	rec := EvidenceRecord{
		Request: EvidenceRequest{
			Method:       "GET",
			URL:          "https://api.example.com/x",
			Headers:      RedactHeaders(http.Header{"X-Trace": {"ok"}}),
			BodyEncoding: "base64",
		},
		Response: EvidenceResponse{
			Status:       200,
			Headers:      http.Header{},
			BodyBase64:   bodyB64,
			BodyEncoding: "base64",
		},
	}
	ref, _, err := es.Write(rec)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ref))
	if err != nil {
		t.Fatalf("baca evidence: %v", err)
	}
	// Kontrol: file utuh lolos verifikasi.
	if !verifyEvidence(raw) {
		t.Fatal("kontrol: evidence utuh harus lolos verifikasi sha256")
	}

	rewrite := func(mutate func(ef *evidenceFile)) []byte {
		t.Helper()
		var ef evidenceFile
		if err := json.Unmarshal(raw, &ef); err != nil {
			t.Fatalf("parse: %v", err)
		}
		mutate(&ef)
		out, err := json.MarshalIndent(ef, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return out
	}

	cases := []struct {
		name string
		data []byte
	}{
		{
			// Flip satu byte mentah di dalam nilai body_base64.
			name: "flip 1 byte raw di body_base64",
			data: func() []byte {
				cp := append([]byte(nil), raw...)
				idx := strings.Index(string(cp), bodyB64)
				if idx < 0 {
					t.Fatal("test bug: substring body tidak ditemukan")
				}
				cp[idx+3] ^= 0x01
				return cp
			}(),
		},
		{
			name: "isi response body diubah, sha256 lama dipertahankan",
			data: rewrite(func(ef *evidenceFile) {
				ef.Response.BodyBase64 = "VEFNUEVSRUQ=" // "TAMPERED"
			}),
		},
		{
			name: "status response diubah",
			data: rewrite(func(ef *evidenceFile) {
				ef.Response.Status = 500
			}),
		},
		{
			name: "seq diubah",
			data: rewrite(func(ef *evidenceFile) {
				ef.Seq = 999
			}),
		},
		{
			name: "field sha256 itu sendiri diubah",
			data: rewrite(func(ef *evidenceFile) {
				ef.SHA256 = strings.Repeat("0", 64)
			}),
		},
		{
			name: "header diubah",
			data: rewrite(func(ef *evidenceFile) {
				ef.Request.Headers["X-Trace"] = []string{"diubah"}
			}),
		},
	}
	for _, tc := range cases {
		if verifyEvidence(tc.data) {
			t.Errorf("BYPASS: verifikasi sha256 LOLOS padahal %s", tc.name)
		}
	}
}

// TestAdversarialEvidenceBinaryBodyNoPanic: body binary (NUL byte, byte UTF-8
// tidak valid, seluruh rentang 0x00-0xFF) disimpan base64 dan di-decode balik
// identik — tanpa panic dan tanpa korupsi.
func TestAdversarialEvidenceBinaryBodyNoPanic(t *testing.T) {
	dir := t.TempDir()
	es, err := NewEvidenceStore(dir)
	if err != nil {
		t.Fatalf("NewEvidenceStore: %v", err)
	}
	// 0x00..0xFF diulang 16x — mencakup NUL, byte kontrol, dan invalid UTF-8.
	var binary []byte
	for i := 0; i < 16; i++ {
		for b := 0; b < 256; b++ {
			binary = append(binary, byte(b))
		}
	}
	rec := EvidenceRecord{
		Request: EvidenceRequest{
			Method:       "POST",
			URL:          "https://api.example.com/upload",
			BodyBase64:   base64.StdEncoding.EncodeToString(binary),
			BodyEncoding: "base64",
		},
		Response: EvidenceResponse{
			Status:       200,
			BodyBase64:   base64.StdEncoding.EncodeToString(binary),
			BodyEncoding: "base64",
		},
	}
	ref, _, err := es.Write(rec)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ref))
	if err != nil {
		t.Fatalf("baca evidence: %v", err)
	}
	var ef evidenceFile
	if err := json.Unmarshal(raw, &ef); err != nil {
		t.Fatalf("parse evidence binary: %v (tidak boleh gagal)", err)
	}
	got, err := base64.StdEncoding.DecodeString(ef.Response.BodyBase64)
	if err != nil {
		t.Fatalf("decode body binary: %v", err)
	}
	if !bytes.Equal(got, binary) {
		t.Error("body binary berubah setelah roundtrip evidence")
	}
}
