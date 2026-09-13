package events

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ErrNotFound dikembalikan (ter-wrapping) bila evidence_ref tidak ada di index
// atau filenya hilang. ErrInvalidRef bila evidence_ref tidak lolos validasi
// (path traversal, pola salah). Pemanggil (mis. internal/mcp) memetakan
// keduanya ke invalid params.
var (
	ErrNotFound   = errors.New("events: evidence_ref tidak ditemukan")
	ErrInvalidRef = errors.New("events: evidence_ref tidak valid")
)

// RedirectSummary ringkasan redirect dari evidence (mirror format proxy).
type RedirectSummary struct {
	Followed bool   `json:"followed"`
	Blocked  bool   `json:"blocked"`
	Location string `json:"location,omitempty"`
	Hops     int    `json:"hops"`
	Reason   string `json:"reason,omitempty"`
}

// HopSummary satu hop outbound ter-capture di evidence.
type HopSummary struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Status int    `json:"status"`
}

// RequestDetail request penuh dari evidence. Header dikembalikan APA ADANYA
// seperti di file (sudah ter-redaksi oleh proxy saat menulis, §24/§25 —
// event store tidak pernah menyimpan header mentah). Body di-decode dari
// base64: teks valid UTF-8 diberikan apa adanya (body_encoding "utf-8");
// binary diberikan tetap base64 (body_encoding "base64").
type RequestDetail struct {
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers,omitempty"`
	Body         string              `json:"body,omitempty"`
	BodyEncoding string              `json:"body_encoding,omitempty"` // utf-8 | base64
}

// ResponseDetail response penuh dari evidence (aturan header/body sama
// dengan RequestDetail).
type ResponseDetail struct {
	Status            int                 `json:"status"`
	Headers           map[string][]string `json:"headers,omitempty"`
	Body              string              `json:"body,omitempty"`
	BodyEncoding      string              `json:"body_encoding,omitempty"` // utf-8 | base64
	BodyHardTruncated bool                `json:"body_hard_truncated,omitempty"`
}

// Detail konten penuh satu evidence — hasil Inspect.
type Detail struct {
	EvidenceRef string            `json:"evidence_ref"`
	Seq         int64             `json:"seq"`
	CapturedAt  string            `json:"captured_at"`
	SHA256      string            `json:"sha256"`
	Provenance  map[string]string `json:"provenance,omitempty"`
	Request     RequestDetail     `json:"request"`
	Response    ResponseDetail    `json:"response"`
	Redirect    RedirectSummary   `json:"redirect"`
	Hops        []HopSummary      `json:"hops,omitempty"`
	LatencyMS   int64             `json:"latency_ms"`
}

// Inspect mengembalikan detail penuh satu evidence berdasarkan evidence_ref
// (nama file relatif di evidence dir, mis. "evidence-000001.json").
// Fail-closed: ref dengan path separator / di luar pola evidence-*.json
// ditolak (path traversal tidak mungkin); sha256 diverifikasi ulang.
func (s *Store) Inspect(evidenceRef string) (*Detail, error) {
	rec, err := s.loadVerified(evidenceRef)
	if err != nil {
		return nil, err
	}
	ref := mustSafeRefName(evidenceRef)
	reqBody, reqEnc, err := decodeBody(rec.Request.BodyBase64)
	if err != nil {
		return nil, fmt.Errorf("events: %s: request body: %w", ref, err)
	}
	respBody, respEnc, err := decodeBody(rec.Response.BodyBase64)
	if err != nil {
		return nil, fmt.Errorf("events: %s: response body: %w", ref, err)
	}
	d := &Detail{
		EvidenceRef: ref,
		Seq:         rec.Seq,
		CapturedAt:  rec.CapturedAt,
		SHA256:      rec.SHA256,
		Provenance:  rec.Provenance,
		Request: RequestDetail{
			Method:       rec.Request.Method,
			URL:          rec.Request.URL,
			Headers:      rec.Request.Headers,
			Body:         reqBody,
			BodyEncoding: reqEnc,
		},
		Response: ResponseDetail{
			Status:            rec.Response.Status,
			Headers:           rec.Response.Headers,
			Body:              respBody,
			BodyEncoding:      respEnc,
			BodyHardTruncated: rec.Response.BodyHardTruncated,
		},
		Redirect: RedirectSummary{
			Followed: rec.Redirect.Followed,
			Blocked:  rec.Redirect.Blocked,
			Location: rec.Redirect.Location,
			Hops:     rec.Redirect.Hops,
			Reason:   rec.Redirect.Reason,
		},
		LatencyMS: rec.LatencyMS,
	}
	for _, h := range rec.Hops {
		d.Hops = append(d.Hops, HopSummary{URL: h.URL, Method: h.Method, Status: h.Status})
	}
	return d, nil
}

// safeRef memvalidasi evidence_ref: nama file biasa tanpa separator, harus
// pola "evidence-*.json" (defense in depth terhadap path traversal, §24).
// Error dibungkus ErrInvalidRef agar pemanggil bisa memetakan ke invalid params.
func safeRef(ref string) (string, error) {
	r := strings.TrimSpace(ref)
	switch {
	case r == "":
		return "", fmt.Errorf("%w: kosong", ErrInvalidRef)
	case r != filepath.Base(r) || strings.ContainsAny(r, `/\`) || r == "." || r == "..":
		return "", fmt.Errorf("%w: %q harus nama file evidence (tanpa path)", ErrInvalidRef, ref)
	case !strings.HasPrefix(r, "evidence-") || !strings.HasSuffix(r, ".json"):
		return "", fmt.Errorf("%w: %q harus pola evidence-*.json", ErrInvalidRef, ref)
	}
	return r, nil
}

// lookup mencari entri index berdasarkan nama file.
func (s *Store) lookup(ref string) (Entry, bool) {
	for _, e := range s.entries {
		if e.EvidenceRef == ref {
			return e, true
		}
	}
	return Entry{}, false
}

// decodeBody mengubah body_base64 evidence menjadi string: UTF-8 valid
// diberikan apa adanya ("utf-8"); binary tetap base64 ("base64").
func decodeBody(b64 string) (body, encoding string, err error) {
	if b64 == "" {
		return "", "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", fmt.Errorf("decode base64: %w", err)
	}
	if utf8.Valid(raw) {
		return string(raw), "utf-8", nil
	}
	return b64, "base64", nil
}

// sha256Hex helper (dipakai events.go juga).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
