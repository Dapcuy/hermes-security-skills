// Package audit mengimplementasikan audit log append-only dengan hash chain
// (ROADMAP 25 — Evidence Integrity; ROADMAP 35 — audit log tamper-evident).
//
// Format: JSONL, satu entry per baris. Setiap entry berisi seq, ts, actor,
// action, detail, prev_hash, dan entry_hash. entry_hash = sha256 dari
// serialisasi JSON entry tanpa field entry_hash. File existing dilanjutkan;
// prev_hash / entry_hash / seq yang tidak cocok = error (fail-closed).
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// GenesisPrevHash adalah prev_hash untuk entry pertama dalam chain.
const GenesisPrevHash = ""

// Entry satu baris audit log.
type Entry struct {
	Seq       int64          `json:"seq"`
	TS        string         `json:"ts"` // RFC3339Nano UTC
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Detail    map[string]any `json:"detail,omitempty"`
	PrevHash  string         `json:"prev_hash"`
	EntryHash string         `json:"entry_hash"`
}

// hashPayload adalah bentuk entry yang di-hash (tanpa EntryHash).
type hashPayload struct {
	Seq      int64          `json:"seq"`
	TS       string         `json:"ts"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	Detail   map[string]any `json:"detail,omitempty"`
	PrevHash string         `json:"prev_hash"`
}

// HashEntry menghitung entry_hash deterministik (sha256 hex).
// encoding/json mengurutkan key map, sehingga hasil selalu stabil.
func HashEntry(e Entry) (string, error) {
	b, err := json.Marshal(hashPayload{
		Seq:      e.Seq,
		TS:       e.TS,
		Actor:    e.Actor,
		Action:   e.Action,
		Detail:   e.Detail,
		PrevHash: e.PrevHash,
	})
	if err != nil {
		return "", fmt.Errorf("audit: marshal payload: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Writer menulis entry ke file JSONL secara append-only.
type Writer struct {
	mu      sync.Mutex
	path    string
	last    Entry
	hasLast bool
}

// Open membuka (atau membuat) audit log. File existing dibaca dan diverifikasi
// penuh — chain rusak = error fail-closed (tidak menimpa, tidak lanjut).
func Open(path string) (*Writer, error) {
	w := &Writer{path: path}
	entries, err := ReadAll(path)
	if err != nil {
		return nil, err
	}
	if len(entries) > 0 {
		w.last = entries[len(entries)-1]
		w.hasLast = true
	}
	return w, nil
}

// Append menambah satu entry ke ujung chain dan menuliskannya ke disk.
func (w *Writer) Append(actor, action string, detail map[string]any) (Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	e := Entry{
		Seq:      1,
		TS:       time.Now().UTC().Format(time.RFC3339Nano),
		Actor:    actor,
		Action:   action,
		Detail:   detail,
		PrevHash: GenesisPrevHash,
	}
	if w.hasLast {
		e.Seq = w.last.Seq + 1
		e.PrevHash = w.last.EntryHash
	}
	h, err := HashEntry(e)
	if err != nil {
		return Entry{}, err
	}
	e.EntryHash = h

	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: marshal entry: %w", err)
	}
	// O_APPEND menjamin append-only di level file.
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: buka %s: %w", w.path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Entry{}, fmt.Errorf("audit: tulis %s: %w", w.path, err)
	}
	w.last = e
	w.hasLast = true
	return e, nil
}

// Verify membaca dan memverifikasi seluruh chain dalam file.
func Verify(path string) error {
	_, err := ReadAll(path)
	return err
}

// ReadAll membaca seluruh entry sambil memverifikasi chain.
// File tidak ada = chain kosong (bukan error). Baris tidak valid,
// prev_hash mismatch, entry_hash mismatch, atau seq tidak berurutan
// = error fail-closed.
func ReadAll(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: baca %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	var out []Entry
	prev := GenesisPrevHash
	for i, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			// Baris kosong hanya ditoleransi sebagai trailing newline terakhir.
			if i == len(lines)-1 {
				continue
			}
			return nil, fmt.Errorf("audit: baris %d kosong", i+1)
		}
		var e Entry
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			return nil, fmt.Errorf("audit: baris %d tidak valid: %w", i+1, err)
		}
		if e.PrevHash != prev {
			return nil, fmt.Errorf("audit: baris %d: prev_hash mismatch (chain putus)", i+1)
		}
		if e.Seq != int64(len(out)+1) {
			return nil, fmt.Errorf("audit: baris %d: seq %d tidak berurutan (harap %d)", i+1, e.Seq, len(out)+1)
		}
		h, err := HashEntry(e)
		if err != nil {
			return nil, err
		}
		if h != e.EntryHash {
			return nil, fmt.Errorf("audit: baris %d: entry_hash mismatch (entry diubah)", i+1)
		}
		prev = e.EntryHash
		out = append(out, e)
	}
	return out, nil
}
