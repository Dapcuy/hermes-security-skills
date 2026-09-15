// Package knowledge mengimplementasikan Knowledge Base curated
// (ROADMAP v3.0 §23, §24, §61 — Phase 11).
//
// Sejak ROADMAP v3.0, "memory" DIHAPUS sebagai komponen utama project
// (§24 Why Skill > Memory): state kasus hidup di evidence + jobs +
// approval + events, BUKAN di memori agent. Package ini hanya mengelola
// knowledge base curated/reference-oriented yang hidup di direktori
// knowledge/ (§23):
//
//	knowledge/
//	├── canonical/        — reference stabil (state=trusted; promosi oleh
//	│                        keputusan owner)
//	├── research/         — hasil ingest, menunggu review (state=proposed)
//	├── methodology/       — curated manual (metodologi, pola reasoning)
//	├── false-positives/   — curated manual (katalog false positive)
//	└── reviewed/         — lolos human review (state=reviewed)
//
// Struktur data:
//   - Entry: satu entri knowledge berformat markdown + frontmatter YAML
//     subset (di-parse via internal/yamlmini) + body.
//   - Store: API filesystem di atas direktori knowledge/.
//
// Lifecycle state (§23):
//
//	captured → normalized → proposed → reviewed → trusted
//	dan sampingan: * → stale, * → archived (archived terminal)
//
// Knowledge firewall (§20, §23): konten target-controlled TIDAK PERNAH
// masuk knowledge base — Store.Ingest menolak fail-closed entry dengan
// provenance.source "target-controlled" (atau trust=untrusted). Konten
// target hidup di evidence (berprovenance, ber-hash), tidak pernah jadi
// "pelajaran" yang diwariskan antar engagement.
//
// Fail-closed: frontmatter tidak valid, field wajib hilang, transisi state
// ilegal, atau path di luar direktori store = error (tidak ada silent
// degrade). Stdlib only.
package knowledge

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"hermes-security-skills/internal/yamlmini"
)

// State lifecycle entry (§23).
type State string

const (
	StateCaptured   State = "captured"
	StateNormalized State = "normalized"
	StateProposed   State = "proposed"
	StateReviewed   State = "reviewed"
	StateTrusted    State = "trusted"
	StateStale      State = "stale"
	StateArchived   State = "archived"
)

// Trust level provenance (§20 content trust).
type Trust string

const (
	TrustTrusted   Trust = "trusted"   // konten yang disusun/direview manusia
	TrustUntrusted Trust = "untrusted" // konten target-controlled (§20)
)

// SourceTargetControlled adalah nilai provenance.source untuk konten yang
// berasal dari target (§20). Cap ini dipakai sistem/evidence pipeline;
// entry yang membawa cap ini TIDAK PERNAH boleh masuk knowledge base —
// Ingest menolaknya fail-closed walau trust dipalsukan trusted.
const SourceTargetControlled = "target-controlled"

// Provenance asal-usul sebuah entry.
type Provenance struct {
	Source string `json:"source"`
	Trust  Trust  `json:"trust"`
}

// Entry satu entri knowledge (§23).
type Entry struct {
	ID           string
	Title        string
	Category     string
	Source       string
	Provenance   Provenance
	Confidence   float64    // 0..1
	State        State      // lifecycle §23
	LastReviewed time.Time  // UTC
	ExpiresAt    *time.Time // opsional
	Body         string     // markdown setelah frontmatter

	// confidenceSet: true bila frontmatter memuat confidence eksplisit —
	// membedakan "penulis belum menilai" dari nilai 0 yang sah.
	confidenceSet bool

	// Path file sumber (diisi saat scan/Get; kosong untuk entry baru).
	Path string
}

// staleAfter: entry yang last_reviewed-nya lebih tua dari ini dianggap
// stale (§61 stale detection).
const staleAfter = 90 * 24 * time.Hour

// MarkStaleHorizon mengembalikan ambang staleness (untuk report CLI).
func MarkStaleHorizon() time.Duration { return staleAfter }

// validStates: enum state yang dikenal.
var validStates = map[State]bool{
	StateCaptured: true, StateNormalized: true, StateProposed: true,
	StateReviewed: true, StateTrusted: true, StateStale: true, StateArchived: true,
}

// ValidState melaporkan apakah state termasuk enum yang dikenal.
func ValidState(s State) bool { return validStates[s] }

// transitions: transisi state VALID (§23). Transisi di luar tabel ini
// ditolak fail-closed oleh SetState.
var transitions = map[State][]State{
	StateCaptured:   {StateNormalized, StateStale, StateArchived},
	StateNormalized: {StateProposed, StateStale, StateArchived},
	StateProposed:   {StateReviewed, StateStale, StateArchived},
	StateReviewed:   {StateTrusted, StateStale, StateArchived},
	StateTrusted:    {StateStale, StateArchived},
	// stale: hasil re-review manusia masuk kembali sebagai reviewed;
	// otherwise arsipkan.
	StateStale: {StateReviewed, StateArchived},
	// archived terminal — tidak ada jalan keluar (fail-closed).
	StateArchived: {},
}

// CanTransition memeriksa apakah transisi from→to valid. State tidak dikenal
// = false (fail-closed).
func CanTransition(from, to State) bool {
	if !validStates[from] || !validStates[to] {
		return false
	}
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// validTrust: enum trust yang dikenal.
var validTrust = map[Trust]bool{
	TrustTrusted: true, TrustUntrusted: true,
}

// isTargetControlled melaporkan apakah entry membawa penanda konten target
// (§20) — baik dari cap provenance.source maupun klaim trust untrusted.
func (e *Entry) isTargetControlled() bool {
	return strings.EqualFold(strings.TrimSpace(e.Provenance.Source), SourceTargetControlled) ||
		strings.EqualFold(strings.TrimSpace(string(e.Provenance.Trust)), string(TrustUntrusted))
}

// validate memeriksa kelengkapan & keabsahan field entry (fail-closed).
// ID divalidasi terpisah (bisa kosong saat file di-ingest — diisi dari
// nama file oleh Store.Ingest).
func (e *Entry) validate() error {
	if e.ID != "" && !isSlug(e.ID) {
		return fmt.Errorf("knowledge: id %q tidak valid (harus slug [a-z0-9] dengan pemisah . _ -)", e.ID)
	}
	// Karakter kontrol tidak boleh masuk frontmatter (akan merusak render
	// round-trip) — kecuali \n dan \t yang didukung escape yamlmini.
	for name, v := range map[string]string{
		"title": e.Title, "category": e.Category, "source": e.Source,
		"provenance.source": e.Provenance.Source,
	} {
		for _, r := range v {
			if r < 0x20 && r != '\n' && r != '\t' {
				return fmt.Errorf("knowledge: %s: field %s mengandung karakter kontrol tidak valid (U+%04X)", e.ID, name, r)
			}
		}
	}
	if strings.TrimSpace(e.Title) == "" {
		return fmt.Errorf("knowledge: %s: title wajib ada", e.ID)
	}
	if strings.TrimSpace(e.Category) == "" {
		return fmt.Errorf("knowledge: %s: category wajib ada", e.ID)
	}
	if strings.TrimSpace(e.Source) == "" {
		return fmt.Errorf("knowledge: %s: source wajib ada", e.ID)
	}
	if strings.TrimSpace(string(e.Provenance.Source)) == "" {
		return fmt.Errorf("knowledge: %s: provenance.source wajib ada", e.ID)
	}
	if !validTrust[e.Provenance.Trust] {
		return fmt.Errorf("knowledge: %s: provenance.trust %q tidak dikenal (trusted|untrusted)", e.ID, e.Provenance.Trust)
	}
	if e.Confidence < 0 || e.Confidence > 1 {
		return fmt.Errorf("knowledge: %s: confidence %g di luar rentang 0..1", e.ID, e.Confidence)
	}
	if e.State != "" && !validStates[e.State] {
		return fmt.Errorf("knowledge: %s: state %q tidak dikenal", e.ID, e.State)
	}
	return nil
}

// complete memvalidasi kelengkapan entry SEBELUM ditulis ke disk
// (field yang boleh absen pada file draf ingest wajib ada saat render).
func (e *Entry) complete() error {
	if err := e.validate(); err != nil {
		return err
	}
	if e.ID == "" {
		return fmt.Errorf("knowledge: id wajib ada sebelum entry ditulis")
	}
	if e.State == "" {
		return fmt.Errorf("knowledge: %s: state wajib ada sebelum entry ditulis", e.ID)
	}
	if e.LastReviewed.IsZero() {
		return fmt.Errorf("knowledge: %s: last_reviewed wajib ada sebelum entry ditulis", e.ID)
	}
	return nil
}

// isSlug memvalidasi id: huruf kecil, digit, dan pemisah . _ -, tidak boleh
// kosong atau mengandung path separator (anti path traversal).
func isSlug(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if s[0] == '.' || s[0] == '-' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// Slugify mengonversi teks bebas menjadi slug id: lowercase, karakter di
// luar [a-z0-9] menjadi '-'. Hasil dibatasi 96 karakter.
func Slugify(s string) string {
	var b strings.Builder
	lastDash := true // cegah dash di depan
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case unicode.IsLetter(r) && r < 128 || unicode.IsDigit(r):
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 96 {
		out = strings.TrimRight(out[:96], "-")
	}
	return out
}

// ---------------------------------------------------------------- frontmatter

// SplitFrontmatter memisahkan markdown menjadi blok frontmatter (di antara
// dua baris "---") dan body. Fail-closed: tanpa pembuka/penutup = error.
func SplitFrontmatter(data []byte) (fmRaw []byte, body string, err error) {
	lines := strings.Split(string(data), "\n")
	i := 0
	for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
		i++
	}
	if i >= len(lines) || strings.TrimRight(lines[i], "\r") != "---" {
		return nil, "", fmt.Errorf("knowledge: frontmatter tidak ditemukan (harus mulai dengan '---')")
	}
	i++
	start := i
	closed := false
	for ; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r") == "---" {
			closed = true
			break
		}
	}
	if !closed {
		return nil, "", fmt.Errorf("knowledge: frontmatter tidak ditutup dengan '---'")
	}
	fmRaw = []byte(strings.Join(lines[start:i], "\n"))
	// Body: sisanya setelah penutup, buang satu newline kosong di awal.
	body = strings.TrimLeft(strings.Join(lines[i+1:], "\n"), "\r\n")
	return fmRaw, body, nil
}

// ParseEntry mem-parse satu file entry markdown+frontmatter menjadi Entry.
// Fail-closed: field wajib hilang / tipe salah / nilai di luar enum = error.
func ParseEntry(data []byte) (*Entry, error) {
	fmRaw, body, err := SplitFrontmatter(data)
	if err != nil {
		return nil, err
	}
	doc, err := yamlmini.Parse(fmRaw)
	if err != nil {
		return nil, fmt.Errorf("knowledge: frontmatter: %w", err)
	}
	e := &Entry{Body: body}
	var err2 error
	// id opsional di file — Store.Ingest mengisinya dari nama file bila kosong.
	if e.ID, err2 = fmString(doc, "id", false); err2 != nil {
		return nil, err2
	}
	if e.Title, err2 = fmString(doc, "title", true); err2 != nil {
		return nil, err2
	}
	if e.Category, err2 = fmString(doc, "category", true); err2 != nil {
		return nil, err2
	}
	if e.Source, err2 = fmString(doc, "source", true); err2 != nil {
		return nil, err2
	}
	if e.State, err2 = fmState(doc, "state", false); err2 != nil {
		return nil, err2
	}
	// provenance: nested map {source, trust}.
	pv, ok := doc["provenance"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("knowledge: frontmatter 'provenance' wajib map {source, trust}")
	}
	if e.Provenance.Source, err2 = fmString(pv, "source", true); err2 != nil {
		return nil, fmt.Errorf("knowledge: provenance: %w", err2)
	}
	trustStr, err2 := fmString(pv, "trust", true)
	if err2 != nil {
		return nil, fmt.Errorf("knowledge: provenance: %w", err2)
	}
	e.Provenance.Trust = Trust(strings.ToLower(trustStr))
	if !validTrust[e.Provenance.Trust] {
		return nil, fmt.Errorf("knowledge: provenance.trust %q tidak dikenal (trusted|untrusted)", trustStr)
	}
	// confidence: float 0..1; opsional pada draf (wajib lewat flag/meta
	// sebelum entry ditulis). yamlmini mengembalikan int atau string.
	if raw, ok := doc["confidence"]; ok && raw != nil {
		if e.Confidence, err2 = fmConfidenceValue(raw, "confidence"); err2 != nil {
			return nil, err2
		}
		e.confidenceSet = true
	}
	// last_reviewed: RFC3339; opsional pada draf (Ingest mengisi now).
	if raw, ok := doc["last_reviewed"]; ok && raw != nil {
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("knowledge: last_reviewed harus string RFC3339")
		}
		if e.LastReviewed, err2 = parseRFC3339(s); err2 != nil {
			return nil, fmt.Errorf("knowledge: last_reviewed: %w", err2)
		}
	}
	// expires_at: RFC3339 opsional.
	if raw, ok := doc["expires_at"]; ok && raw != nil {
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("knowledge: expires_at harus string RFC3339")
		}
		t, err := parseRFC3339(s)
		if err != nil {
			return nil, fmt.Errorf("knowledge: expires_at: %w", err)
		}
		e.ExpiresAt = &t
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return e, nil
}

func parseRFC3339(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, fmt.Errorf("bukan timestamp RFC3339: %q", s)
	}
	return t.UTC(), nil
}

func fmString(doc map[string]any, key string, required bool) (string, error) {
	v, ok := doc[key]
	if !ok || v == nil {
		if required {
			return "", fmt.Errorf("knowledge: frontmatter %q wajib ada", key)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("knowledge: frontmatter %q harus string", key)
	}
	if required && strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("knowledge: frontmatter %q tidak boleh kosong", key)
	}
	return s, nil
}

func fmState(doc map[string]any, key string, required bool) (State, error) {
	s, err := fmString(doc, key, required)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", nil // state opsional pada draf; wajib saat render
	}
	st := State(strings.ToLower(strings.TrimSpace(s)))
	if !validStates[st] {
		return "", fmt.Errorf("knowledge: state %q tidak dikenal (captured|normalized|proposed|reviewed|trusted|stale|archived)", s)
	}
	return st, nil
}

func fmConfidenceValue(v any, key string) (float64, error) {
	var f float64
	switch n := v.(type) {
	case int:
		f = float64(n)
	case string:
		p, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil {
			return 0, fmt.Errorf("knowledge: frontmatter %q harus angka", key)
		}
		f = p
	default:
		return 0, fmt.Errorf("knowledge: frontmatter %q harus angka", key)
	}
	if f < 0 || f > 1 {
		return 0, fmt.Errorf("knowledge: frontmatter %q di luar rentang 0..1", key)
	}
	return f, nil
}

// renderEntry menulis Entry kembali menjadi markdown+frontmatter yang bisa
// di-parse ParseEntry (round-trip). Nilai string di-quote bila perlu agar
// tetap valid di subset yamlmini. Entry harus lengkap (complete()).
func renderEntry(e *Entry) ([]byte, error) {
	if err := e.complete(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "id: %s\n", e.ID)
	fmt.Fprintf(&b, "title: %s\n", quoteYAML(e.Title))
	fmt.Fprintf(&b, "category: %s\n", quoteYAML(e.Category))
	fmt.Fprintf(&b, "source: %s\n", quoteYAML(e.Source))
	fmt.Fprintf(&b, "confidence: %s\n", strconv.FormatFloat(e.Confidence, 'f', -1, 64))
	fmt.Fprintf(&b, "state: %s\n", e.State)
	fmt.Fprintf(&b, "last_reviewed: %s\n", e.LastReviewed.UTC().Format(time.RFC3339))
	if e.ExpiresAt != nil {
		fmt.Fprintf(&b, "expires_at: %s\n", e.ExpiresAt.UTC().Format(time.RFC3339))
	}
	b.WriteString("provenance:\n")
	fmt.Fprintf(&b, "  source: %s\n", quoteYAML(e.Provenance.Source))
	fmt.Fprintf(&b, "  trust: %s\n", e.Provenance.Trust)
	b.WriteString("---\n\n")
	body := e.Body
	if body != "" && !strings.HasPrefix(body, "\n") {
		b.WriteString("\n")
	}
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
	return []byte(b.String()), nil
}

// quoteYAML: plain bila aman, double-quoted bila mengandung karakter
// khusus. Escape dibatasi pada yang didukung yamlmini (\" \\ \n \t);
// karakter kontrol lain ditolak (fail-closed, bukan escape diam-diam).
func quoteYAML(s string) string {
	if s == "" {
		return `""`
	}
	plain := true
	for _, r := range s {
		if unicode.IsLetter(r) && r < 128 || unicode.IsDigit(r) ||
			r == '.' || r == '_' || r == '-' || r == '/' || r == ' ' {
			continue
		}
		plain = false
		break
	}
	if plain {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			// Karakter kontrol lain sudah ditolak oleh validate(); di sini
			// tulis apa adanya (non-ASCII printable valid di YAML UTF-8).
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
