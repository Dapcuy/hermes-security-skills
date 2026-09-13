// File-based approval store (ROADMAP 9/10 — scoped approval + kill switch).
//
// Store menyimpan approval sebagai satu file JSON (default jobs/approvals.json
// atau --state-dir). Berbeda dengan Approval in-memory, Record bersifat
// serializable sehingga bisa dipakai lintas proses: cmd abort mencabut
// approval case, dan MCP server (serve --mcp) memeriksa approval aktif
// pada jalur enforcement.
//
// Fail-closed: file korup = error (tidak pernah di-reset diam-diam),
// field wajib kosong = Save ditolak, approval kadaluarsa/revoked/habis
// tidak pernah dianggap aktif.
package approval

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PathAny adalah nilai path wildcard eksplisit pada Record: approval berlaku
// untuk semua path pada host tersebut. Harus diset sengaja — kosong ditolak.
const PathAny = "*"

// Record adalah satu approval ter-scope dalam bentuk serializable.
type Record struct {
	ID           string    `json:"id"`
	CaseID       string    `json:"case_id"`
	Capability   string    `json:"capability"`
	Host         string    `json:"host"`
	Method       string    `json:"method"`
	Path         string    `json:"path"` // PathAny ("*") atau path spesifik diawali "/"
	MaxRequests  int       `json:"max_requests"`
	AccountRef   string    `json:"account_ref,omitempty"` // credential reference, bukan nilai (§23)
	ExpiresAt    time.Time `json:"expires_at"`
	Risk         string    `json:"risk"`
	CreatedAt    time.Time `json:"created_at"`
	Used         int       `json:"used"`
	Revoked      bool      `json:"revoked"`
	RevokedAt    time.Time `json:"revoked_at,omitempty"`
	RevokeReason string    `json:"revoke_reason,omitempty"`
}

// ReasonRevokedByAbort adalah alasan standar pencabutan oleh kill switch
// (ROADMAP 10) — ditulis ke store dan audit.
const ReasonRevokedByAbort = "revoked-by-abort"

// validateRecord memeriksa field wajib (fail-closed).
func validateRecord(r Record) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("approval: record.id wajib diisi")
	}
	if strings.TrimSpace(r.CaseID) == "" {
		return fmt.Errorf("approval: record.case_id wajib diisi")
	}
	if strings.TrimSpace(r.Capability) == "" {
		return fmt.Errorf("approval: record.capability wajib diisi")
	}
	if strings.TrimSpace(r.Host) == "" {
		return fmt.Errorf("approval: record.host wajib diisi")
	}
	if strings.TrimSpace(r.Method) == "" {
		return fmt.Errorf("approval: record.method wajib diisi")
	}
	if strings.TrimSpace(r.Path) == "" {
		return fmt.Errorf("approval: record.path wajib diisi (path spesifik atau %q)", PathAny)
	}
	if !strings.HasPrefix(r.Path, "/") && r.Path != PathAny {
		return fmt.Errorf("approval: record.path %q harus diawali \"/\" atau %q", r.Path, PathAny)
	}
	if r.MaxRequests <= 0 {
		return fmt.Errorf("approval: record.max_requests harus > 0")
	}
	if r.ExpiresAt.IsZero() {
		return fmt.Errorf("approval: record.expires_at wajib diisi")
	}
	if strings.TrimSpace(r.Risk) == "" {
		return fmt.Errorf("approval: record.risk wajib diisi")
	}
	return nil
}

// activeAt melaporkan apakah record masih aktif pada waktu now:
// belum dicabut, belum kadaluarsa, dan budget masih ada.
func (r Record) activeAt(now time.Time) bool {
	return !r.Revoked && now.Before(r.ExpiresAt) && r.Used < r.MaxRequests
}

// Store approval berbasis file JSON. Aman dipakai ulang; I/O dilakukan
// per operasi sehingga lintas proses (CLI abort vs MCP server) selalu
// membaca state terbaru.
type Store struct {
	mu   sync.Mutex
	path string
}

// OpenStore membuat Store yang menunjuk file JSON path. Tidak ada I/O
// pada constructor — file dibuat lazily saat Save pertama.
func OpenStore(path string) *Store {
	return &Store{path: path}
}

// Path lokasi file store.
func (s *Store) Path() string { return s.path }

// Save menambah satu record (validasi fail-closed) dan mempersist file.
// ID kosong digenerate otomatis (hex acak). Duplicate ID = error.
func (s *Store) Save(rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(rec.ID) == "" {
		id, err := newRecordID()
		if err != nil {
			return err
		}
		rec.ID = id
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	rec.Method = strings.ToUpper(strings.TrimSpace(rec.Method))
	if err := validateRecord(rec); err != nil {
		return err
	}
	recs, err := s.readLocked()
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.ID == rec.ID {
			return fmt.Errorf("approval: record id %q sudah ada", rec.ID)
		}
	}
	recs = append(recs, rec)
	return s.writeLocked(recs)
}

// Load membaca semua record dari file. File belum ada = store kosong
// (bukan error); file korup / bukan JSON = error fail-closed.
func (s *Store) Load() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked()
}

// RevokeCase mencabut SEMUA approval untuk satu case (ROADMAP 10 — kill
// switch). Idempotent: record yang sudah dicabut tidak dihitung ulang.
// reason dicatat pada record (mis. ReasonRevokedByAbort).
func (s *Store) RevokeCase(caseID, reason string) (int, error) {
	if strings.TrimSpace(caseID) == "" {
		return 0, fmt.Errorf("approval: case_id wajib diisi")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "revoked"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.readLocked()
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	n := 0
	changed := false
	for i := range recs {
		if recs[i].CaseID == caseID && !recs[i].Revoked {
			recs[i].Revoked = true
			recs[i].RevokedAt = now
			recs[i].RevokeReason = reason
			n++
			changed = true
		}
	}
	if changed {
		if err := s.writeLocked(recs); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// Active mengembalikan semua approval aktif untuk satu case pada waktu now:
// belum dicabut, belum kadaluarsa, budget masih ada (ROADMAP 9).
func (s *Store) Active(caseID string) ([]Record, error) {
	if strings.TrimSpace(caseID) == "" {
		return nil, fmt.Errorf("approval: case_id wajib diisi")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var out []Record
	for _, r := range recs {
		if r.CaseID == caseID && r.activeAt(now) {
			out = append(out, r)
		}
	}
	return out, nil
}

// FindActive mencari satu approval aktif yang mencakup permintaan
// (case, capability, host, method, path). Case wajib match exact —
// approval terikat engagement (§9), tidak boleh dipakai case lain.
// Path dicocokkan exact kecuali record memakai PathAny. Record yang
// ditemukan BELUM dikonsumsi — panggil Consume untuk memotong budget
// (dua langkah agar caller bisa audit dulu). Tidak ada match = nil, nil
// (bukan error).
func (s *Store) FindActive(capabilityName, caseID, host, method, path string) (*Record, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if path == "" {
		path = "/"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var best *Record
	for i := range recs {
		r := recs[i]
		if !r.activeAt(now) {
			continue
		}
		if r.CaseID != caseID || r.Capability != capabilityName || r.Host != host || r.Method != method {
			continue
		}
		if r.Path != PathAny && r.Path != path {
			continue
		}
		// Record dengan budget sisa paling kecil dipilih dulu (consume
		// budget sempit sebelum yang longgar).
		if best == nil || r.MaxRequests-r.Used < best.MaxRequests-best.Used {
			best = &recs[i]
		}
	}
	return best, nil
}

// Consume memotong request budget satu unit untuk record id (ROADMAP 9 —
// request budget). Fail-closed: revoked/expired/habis = error dan state
// tidak berubah.
func (s *Store) Consume(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.readLocked()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for i := range recs {
		if recs[i].ID != id {
			continue
		}
		r := &recs[i]
		switch {
		case r.Revoked:
			return fmt.Errorf("%w (id %s, alasan: %s)", ErrRevoked, id, r.RevokeReason)
		case !now.Before(r.ExpiresAt):
			return fmt.Errorf("%w (id %s)", ErrExpired, id)
		case r.Used >= r.MaxRequests:
			return fmt.Errorf("%w (id %s)", ErrExhausted, id)
		}
		r.Used++
		return s.writeLocked(recs)
	}
	return fmt.Errorf("approval: record id %q tidak ditemukan", id)
}

// readLocked membaca + parse file store. Pemanggil wajib memegang s.mu.
func (s *Store) readLocked() ([]Record, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("approval: baca store %s: %w", s.path, err)
	}
	var recs []Record
	if err := json.Unmarshal(data, &recs); err != nil {
		// Fail-closed: store korup tidak pernah di-reset diam-diam.
		return nil, fmt.Errorf("approval: parse store %s: %w", s.path, err)
	}
	return recs, nil
}

// writeLocked mempersist store secara atomik (tulis temp + rename) agar
// pembaca lintas proses tidak melihat file setengah tertulis.
// Pemanggil wajib memegang s.mu.
func (s *Store) writeLocked(recs []Record) error {
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return fmt.Errorf("approval: marshal store: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("approval: buat direktori %s: %w", dir, err)
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("approval: tulis %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("approval: rename %s -> %s: %w", tmp, s.path, err)
	}
	return nil
}

// newRecordID menghasilkan ID acak hex 16 karakter.
func newRecordID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("approval: generate id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
