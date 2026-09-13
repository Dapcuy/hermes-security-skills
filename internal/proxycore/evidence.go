package proxycore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EvidenceStore menulis evidence file per eksekusi (ROADMAP §25, Phase 7.4):
// evidence-<seq>.json berisi request/response penuh + sha256 + captured_at +
// provenance {component: hermes-proxy}. Evidence di-hash saat dibuat agar
// tampering terdeteksi (§25 Evidence Integrity).
type EvidenceStore struct {
	dir string
	mu  sync.Mutex
	seq int64
}

// EvidenceRequest adalah request penuh yang dicatat di evidence.
// Header SUDAH diredaksi. Body disimpan base64 agar binary-safe.
type EvidenceRequest struct {
	Method       string      `json:"method"`
	URL          string      `json:"url"`
	Headers      http.Header `json:"headers"`
	BodyBase64   string      `json:"body_base64"`
	BodyEncoding string      `json:"body_encoding"`
}

// EvidenceResponse adalah response penuh yang dicatat di evidence.
// Header SUDAH diredaksi. Body penuh (bukan ter-truncate) disimpan base64.
type EvidenceResponse struct {
	Status            int         `json:"status"`
	Headers           http.Header `json:"headers"`
	BodyBase64        string      `json:"body_base64"`
	BodyEncoding      string      `json:"body_encoding"`
	BodyHardTruncated bool        `json:"body_hard_truncated,omitempty"`
}

// EvidenceRecord adalah konten evidence file (tanpa field sha256; sha256
// dihitung ATAS konten ini lalu ditambahkan sebagai field terpisah).
type EvidenceRecord struct {
	Seq        int64             `json:"seq"`
	CapturedAt string            `json:"captured_at"`
	Provenance map[string]string `json:"provenance"`
	Request    EvidenceRequest   `json:"request"`
	Response   EvidenceResponse  `json:"response"`
	Redirect   RedirectInfo      `json:"redirect"`
	Hops       []HopSummary      `json:"hops,omitempty"`
	LatencyMS  int64             `json:"latency_ms"`
}

// evidenceFile adalah bentuk final evidence-<seq>.json.
type evidenceFile struct {
	EvidenceRecord
	SHA256 string `json:"sha256"`
}

// NewEvidenceStore menyiapkan direktori evidence (dibuat bila belum ada).
func NewEvidenceStore(dir string) (*EvidenceStore, error) {
	if dir == "" {
		dir = "jobs/evidence"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("proxycore: siapkan evidence dir %s: %w", dir, err)
	}
	return &EvidenceStore{dir: dir}, nil
}

// Dir mengembalikan path direktori evidence.
func (s *EvidenceStore) Dir() string { return s.dir }

// Write mempersist satu evidence record. Mengembalikan (nama file relatif,
// sha256 hex konten evidence). Dipanggil setiap eksekusi (Mode 1 maupun MITM).
func (s *EvidenceStore) Write(rec EvidenceRecord) (ref, sha string, err error) {
	s.mu.Lock()
	s.seq++
	seq := s.seq
	s.mu.Unlock()
	rec.Seq = seq
	rec.CapturedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if rec.Provenance == nil {
		rec.Provenance = map[string]string{}
	}
	rec.Provenance["component"] = "hermes-proxy"

	// sha256 dihitung atas konten evidence TANPA field sha256 (§25).
	core, err := json.Marshal(rec)
	if err != nil {
		return "", "", fmt.Errorf("proxycore: marshal evidence: %w", err)
	}
	sum := sha256.Sum256(core)

	data, err := json.MarshalIndent(evidenceFile{EvidenceRecord: rec, SHA256: hex.EncodeToString(sum[:])}, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("proxycore: marshal evidence file: %w", err)
	}
	name := fmt.Sprintf("evidence-%06d.json", seq)
	path := filepath.Join(s.dir, name)
	// 0600: evidence boleh memuat konten target; akses seminimal mungkin.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", "", fmt.Errorf("proxycore: tulis evidence %s: %w", path, err)
	}
	return name, hex.EncodeToString(sum[:]), nil
}
