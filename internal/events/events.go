// Package events — event store read-only di atas evidence hermes-proxy
// (ROADMAP §11, §25). hermes-proxy menulis satu evidence-<seq>.json per
// eksekusi (internal/proxycore); package ini TIDAK menulis evidence — ia
// membangun INDEX in-memory di atas file yang sudah ada dan melayani
// capability read-only control plane:
//
//	list_history / inspect_request / compare_responses (§11 Capability Mapping)
//
// Semua operasi murni baca: tidak ada traffic ke target, tidak ada modifikasi
// evidence. Integritas diverifikasi saat index dibangun: sha256 yang dicatat
// proxy di evidence dicek ulang (§25 Evidence Integrity); mismatch = error
// fail-closed. Stdlib only.
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultDir direktori evidence default (sama dengan default hermes-proxy).
const DefaultDir = "jobs/evidence"

// Entry satu baris index event store: ringkasan satu eksekusi ter-capture.
// case_id kosong — evidence file proxy saat ini tidak membawa case id;
// field disiapkan untuk format evidence berikutnya (opsional di §25).
type Entry struct {
	Seq         int64  `json:"seq"`
	TS          string `json:"ts"` // captured_at dari evidence (RFC3339Nano)
	URL         string `json:"url"`
	Method      string `json:"method"`
	Status      int    `json:"status"`
	EvidenceRef string `json:"evidence_ref"` // nama file relatif di evidence dir
	SHA256      string `json:"sha256"`       // sha256 evidence (tercatat proxy, terverifikasi saat load)
	CaseID      string `json:"case_id,omitempty"`
}

// ListFilter filter untuk List. Zero value = tanpa filter (semua entri).
type ListFilter struct {
	Limit        int    // <=0 = semua; bila lebih kecil dari hasil, entri TERBARU yang dipertahankan
	URLSubstring string // URL harus mengandung substring (case-insensitive)
	Method       string // HTTP method exact, case-insensitive
	StatusMin    int    // status >= StatusMin (0/1 = tanpa filter)
}

// Observation satu temuan diff — struktur SAMA dengan kontrak validator
// (schemas/validation-result.json, cmd/validator-http): {type, detail}.
type Observation struct {
	Type   string `json:"type"` // status_diff | header_diff | body_diff | json_diff
	Detail string `json:"detail"`
}

// Store index in-memory atas evidence-*.json dalam satu direktori.
// Immutable setelah LoadEvidenceDir: pembacaan selalu konsisten; index baru
// didapat dengan memanggil LoadEvidenceDir lagi (cache membuatnya murah).
type Store struct {
	dir     string
	entries []Entry // terurut menaik by seq
}

// LoadEvidenceDir memindai dir untuk evidence-*.json, memverifikasi
// integritas, dan membangun index in-memory. dir kosong = DefaultDir.
// Cache index.jsonl dipakai bila fingerprint KONTEN direktori masih cocok
// (lihat cache.go); cache hanya optimasi — kegagalannya tidak fatal, dan
// tampering konten selalu memicu rebuild + penolakan fail-closed (§25).
func LoadEvidenceDir(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultDir
	}
	// Fail-closed: dir tidak ada / bukan direktori = error eksplisit
	// (flag salah harus terlihat, bukan index kosong senyap).
	fi, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("events: evidence dir %s tidak ada", dir)
		}
		return nil, fmt.Errorf("events: stat %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("events: %s bukan direktori", dir)
	}
	entries, err := buildIndex(dir)
	if err != nil {
		return nil, err
	}
	return &Store{dir: dir, entries: entries}, nil
}

// Dir mengembalikan path direktori evidence yang diindeks.
func (s *Store) Dir() string { return s.dir }

// Count jumlah entri di index.
func (s *Store) Count() int { return len(s.entries) }

// Entries mengembalikan salinan index lengkap (terurut menaik by seq).
func (s *Store) Entries() []Entry {
	out := make([]Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// List mengembalikan ringkasan entri yang lolos filter, terurut menaik
// by seq (kronologis). Bila filter menghasilkan lebih dari f.Limit entri,
// Limit entri TERBARU (seq tertinggi) yang dipertahankan — tetap terurut
// menaik agar konsumen tidak perlu membalik.
func (s *Store) List(f ListFilter) []Entry {
	method := strings.ToUpper(strings.TrimSpace(f.Method))
	sub := strings.ToLower(strings.TrimSpace(f.URLSubstring))
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if sub != "" && !strings.Contains(strings.ToLower(e.URL), sub) {
			continue
		}
		if method != "" && e.Method != method {
			continue
		}
		if f.StatusMin > 1 && e.Status < f.StatusMin {
			continue
		}
		out = append(out, e)
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[len(out)-f.Limit:]
	}
	return out
}

// ---------------------------------------------------------------- format file

// coreRecord mirror field evidence core proxycore.EvidenceRecord — urutan dan
// tag JSON WAJIB identik agar sha256 terverifikasi ulang dengan hasil sama
// (sha256 dihitung atas konten core TANPA field sha256, §25).
type coreRecord struct {
	Seq        int64             `json:"seq"`
	CapturedAt string            `json:"captured_at"`
	Provenance map[string]string `json:"provenance"`
	Request    rawRequest        `json:"request"`
	Response   rawResponse       `json:"response"`
	Redirect   rawRedirect       `json:"redirect"`
	Hops       []rawHop          `json:"hops,omitempty"`
	LatencyMS  int64             `json:"latency_ms"`
}

// rawRecord bentuk penuh evidence-<seq>.json (core + sha256).
type rawRecord struct {
	coreRecord
	SHA256 string `json:"sha256"`
}

type rawRequest struct {
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers"`
	BodyBase64   string              `json:"body_base64"`
	BodyEncoding string              `json:"body_encoding"`
}

type rawResponse struct {
	Status            int                 `json:"status"`
	Headers           map[string][]string `json:"headers"`
	BodyBase64        string              `json:"body_base64"`
	BodyEncoding      string              `json:"body_encoding"`
	BodyHardTruncated bool                `json:"body_hard_truncated,omitempty"`
}

type rawRedirect struct {
	Followed bool   `json:"followed"`
	Blocked  bool   `json:"blocked"`
	Location string `json:"location,omitempty"`
	Hops     int    `json:"hops"`
	Reason   string `json:"reason,omitempty"`
}

type rawHop struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Status int    `json:"status"`
}

// buildIndex memindai dir (glob evidence-*.json) dan memverifikasi tiap file.
// Setiap file dibaca SEKALI di sini untuk menghitung hash konten — fingerprint
// cache berbasis konten sehingga tamper (walau mtime dipulihkan attacker)
// selalu memicu rebuild + verifikasi sha256 (§25). Hashing per load lebih
// murah daripada parse JSON; cache tetap menghemat bagian termahal.
func buildIndex(dir string) ([]Entry, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "evidence-*.json"))
	if err != nil {
		return nil, fmt.Errorf("events: glob %s: %w", dir, err)
	}
	sort.Strings(matches)

	// Baca + hash semua file (fail-closed: stat/read gagal = error eksplisit).
	files := make([]fileMeta, 0, len(matches))
	datas := make([][]byte, len(matches))
	for i, p := range matches {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("events: stat %s: %w", p, err)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("events: baca %s: %w", p, err)
		}
		sum := sha256.Sum256(data)
		files = append(files, fileMeta{name: fi.Name(), size: fi.Size(), hash: hex.EncodeToString(sum[:])})
		datas[i] = data
	}
	fp := fingerprint(files)

	if cached, ok := readCache(dir, fp); ok {
		return cached, nil
	}

	entries := make([]Entry, 0, len(matches))
	for i, p := range matches {
		rec, err := parseAndVerify(datas[i])
		if err != nil {
			return nil, fmt.Errorf("events: %s: %w", filepath.Base(p), err)
		}
		entries = append(entries, Entry{
			Seq:         rec.Seq,
			TS:          rec.CapturedAt,
			URL:         rec.Request.URL,
			Method:      rec.Request.Method,
			Status:      rec.Response.Status,
			EvidenceRef: filepath.Base(p),
			SHA256:      rec.SHA256,
		})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Seq < entries[j].Seq })

	// Cache index (best-effort — kegagalan tulis tidak boleh menggagalkan load).
	_ = writeCache(dir, fp, entries)
	return entries, nil
}

// parseAndVerify meng-unmarshal satu evidence file dan memverifikasi sha256
// atas konten core (tanpa field sha256) — sama dengan cara proxy menghitung
// saat menulis (§25 Evidence Integrity).
func parseAndVerify(data []byte) (rawRecord, error) {
	var rec rawRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return rawRecord{}, fmt.Errorf("parse evidence: %w", err)
	}
	if strings.TrimSpace(rec.SHA256) == "" {
		return rawRecord{}, fmt.Errorf("evidence tanpa sha256 ditolak (§25 Evidence Integrity)")
	}
	core, err := json.Marshal(rec.coreRecord)
	if err != nil {
		return rawRecord{}, fmt.Errorf("re-marshal core evidence: %w", err)
	}
	sum := sha256Hex(core)
	if !strings.EqualFold(sum, rec.SHA256) {
		return rawRecord{}, fmt.Errorf("integritas evidence gagal: sha256 tidak cocok (tercatat %s, hitung ulang %s) — evidence dimodifikasi? (§25)", rec.SHA256, sum)
	}
	return rec, nil
}
