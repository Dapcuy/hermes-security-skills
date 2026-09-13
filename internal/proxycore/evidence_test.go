package proxycore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
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
