package knowledge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Kesalahan sentinel (dapat diperiksa pemanggil dengan errors.Is).
var (
	// ErrNotFound: entry tidak ditemukan di store.
	ErrNotFound = errors.New("knowledge: tidak ditemukan")
	// ErrInvalidTransition: transisi state tidak valid (fail-closed, §23).
	ErrInvalidTransition = errors.New("knowledge: transisi state tidak valid")
	// ErrFirewall: pelanggaran knowledge firewall (§20, §23) — konten
	// target-controlled mencoba masuk ke knowledge base.
	ErrFirewall = errors.New("knowledge: knowledge firewall (§20/§23) menolak operasi")
)

// Store adalah pipeline knowledge base di atas filesystem (§23):
//
//	<root>/               — direktori knowledge/ (canonical, research,
//	                        methodology, false-positives, reviewed)
//
// Pemetaan state → direktori:
//
//	captured|normalized|proposed → <root>/research/
//	reviewed                     → <root>/reviewed/
//	trusted                      → <root>/canonical/ (promosi oleh
//	                               keputusan owner)
//	stale|archived               → tetap di direktori semula (frontmatter saja)
//
// methodology/ dan false-positives/ adalah direktori curated manual —
// diisi lewat review/commit manusia, bukan hasil ingest otomatis, tetapi
// tetap ikut di-scan oleh List/Get/Search.
type Store struct {
	Root string // root direktori knowledge
}

// NewStore membangun Store dari root knowledge.
func NewStore(root string) *Store {
	return &Store{Root: root}
}

// scanDirs: direktori resmi knowledge base (§23) yang di-scan. Direktori
// tak ada = diabaikan (store baru yang masih kosong).
func (s *Store) scanDirs() []string {
	return []string{
		filepath.Join(s.Root, "canonical"),
		filepath.Join(s.Root, "research"),
		filepath.Join(s.Root, "methodology"),
		filepath.Join(s.Root, "false-positives"),
		filepath.Join(s.Root, "reviewed"),
	}
}

// knowledgeDir menentukan direktori tujuan untuk entry dengan state tertentu.
func (s *Store) knowledgeDir(st State) string {
	switch st {
	case StateReviewed:
		return filepath.Join(s.Root, "reviewed")
	case StateTrusted:
		return filepath.Join(s.Root, "canonical")
	default:
		// captured, normalized, proposed (dan default konservatif).
		return filepath.Join(s.Root, "research")
	}
}

// IngestMeta metadata ingest yang disediakan manusia (CLI).
type IngestMeta struct {
	Category   string     // wajib (bila kosong, pakai frontmatter)
	Source     string     // wajib (bila kosong, pakai frontmatter)
	Confidence *float64   // nil = pakai frontmatter
	ExpiresAt  *time.Time // opsional
}

// Ingest memvalidasi file entry lalu memindahkannya ke knowledge/research/
// (§23 knowledge ingestion). State hasil ingest dibatasi captured|normalized|
// proposed — reviewed/trusted TIDAK boleh dicapai lewat ingest agar tetap
// melewati human review (§23 lifecycle; promosi ke canonical adalah
// keputusan owner).
//
// Firewall (§20, §23): entry dengan provenance.source "target-controlled"
// atau trust=untrusted DITOLAK fail-closed — konten target tidak boleh masuk
// knowledge base melalui jalur apapun; konten target hidup di evidence
// (berprovenance, ber-hash). Cap "target-controlled" adalah cap SISTEM:
// file yang membawanya tidak diterima walau frontmatter-nya memalsukan
// trust=trusted — mengganti klaim trust tanpa mengganti sumber bukan review
// sungguhan (review manusia yang sah menulis ulang sumbernya).
func (s *Store) Ingest(path string, meta IngestMeta) (*Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("knowledge: baca %s: %w", path, err)
	}
	e, err := ParseEntry(data)
	if err != nil {
		return nil, fmt.Errorf("knowledge: %s: %w", path, err)
	}
	// id opsional di frontmatter: turunkan dari nama file bila kosong.
	if e.ID == "" {
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		e.ID = Slugify(base)
	}
	if !isSlug(e.ID) {
		return nil, fmt.Errorf("knowledge: %s: id turunan %q tidak valid", path, e.ID)
	}
	// Override metadata dari flag CLI (nilai eksplisit menang).
	if strings.TrimSpace(meta.Category) != "" {
		e.Category = strings.TrimSpace(meta.Category)
	}
	if strings.TrimSpace(meta.Source) != "" {
		e.Source = strings.TrimSpace(meta.Source)
	}
	if meta.Confidence != nil {
		e.Confidence = *meta.Confidence
	} else if !e.confidenceSet {
		return nil, fmt.Errorf("knowledge: %s: confidence wajib ada (frontmatter atau --confidence)", path)
	}
	if meta.ExpiresAt != nil {
		t := meta.ExpiresAt.UTC()
		e.ExpiresAt = &t
	}
	if err := e.validate(); err != nil {
		return nil, fmt.Errorf("knowledge: %s: %w", path, err)
	}
	// Knowledge firewall (§20, §23): konten target tidak masuk knowledge
	// base — titik. Tidak ada direktori penampung target di package ini;
	// konten target hidup di evidence.
	if e.isTargetControlled() {
		return nil, fmt.Errorf("%w: entry %s berasal dari target (provenance.source=%q, trust=%q) — target-controlled content tidak boleh masuk knowledge base; konten target hidup di evidence (§20, §23)", ErrFirewall, e.ID, e.Provenance.Source, e.Provenance.Trust)
	}
	// Human-in-the-loop: ingest hanya boleh menghasilkan state pra-review.
	switch e.State {
	case "", StateCaptured, StateNormalized, StateProposed:
		// Setelah tervalidasi, entry masuk pipeline sebagai proposed.
		e.State = StateProposed
	default:
		return nil, fmt.Errorf("knowledge: %s: ingest tidak boleh menetapkan state %q (hanya captured|normalized|proposed; reviewed/trusted lewat review manusia, §23)", path, e.State)
	}
	if e.LastReviewed.IsZero() {
		e.LastReviewed = time.Now().UTC()
	}
	if err := s.writeEntry(e, s.knowledgeDir(e.State)); err != nil {
		return nil, err
	}
	dstAbs, err := filepath.Abs(entryPath(s.knowledgeDir(e.State), e.ID))
	if err != nil {
		return nil, err
	}
	// Move semantics: hapus file sumber bila berbeda dari tujuan.
	srcAbs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if srcAbs != dstAbs {
		if err := os.Remove(srcAbs); err != nil {
			return nil, fmt.Errorf("knowledge: hapus sumber %s: %w", path, err)
		}
	}
	e.Path = dstAbs
	return e, nil
}

// entryPath menyusun path file entry (id sudah tervalidasi slug — aman).
func entryPath(dir, id string) string {
	return filepath.Join(dir, id+".md")
}

// writeEntry merender dan menulis entry ke dir/<id>.md. Fail-closed:
// tujuan sudah ada = error (tidak pernah menimpa secara senyap).
func (s *Store) writeEntry(e *Entry, dir string) error {
	if !isSlug(e.ID) {
		return fmt.Errorf("knowledge: id %q tidak valid", e.ID)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("knowledge: buat direktori %s: %w", dir, err)
	}
	dst := entryPath(dir, e.ID)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("knowledge: entry %s sudah ada di %s (tidak menimpa)", e.ID, dst)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("knowledge: cek %s: %w", dst, err)
	}
	data, err := renderEntry(e)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("knowledge: tulis %s: %w", dst, err)
	}
	return nil
}

// Filter penyaring List (string kosong = tanpa filter).
type Filter struct {
	State    State
	Category string
}

// List mengembalikan semua entry knowledge yang lolos filter, terurut by id
// (deterministik). Entry tidak parseable = error fail-closed.
func (s *Store) List(f Filter) ([]*Entry, error) {
	var out []*Entry
	seen := map[string]bool{}
	for _, dir := range s.scanDirs() {
		if err := scanEntries(dir, func(e *Entry) error {
			if !seen[e.ID] {
				seen[e.ID] = true
				out = append(out, e)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	// Terapkan filter di memori agar deterministik.
	var res []*Entry
	for _, e := range out {
		if f.State != "" && e.State != f.State {
			continue
		}
		if f.Category != "" && !strings.EqualFold(e.Category, f.Category) {
			continue
		}
		res = append(res, e)
	}
	return res, nil
}

// scanEntries mem-parse semua *.md pada satu direktori (non-rekursif).
func scanEntries(dir string, fn func(*Entry) error) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("knowledge: baca %s: %w", dir, err)
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
			continue
		}
		// README.md adalah dokumentasi direktori (bukan entry knowledge) —
		// dilewati; file .md lain yang tidak parseable tetap error
		// fail-closed.
		if f.Name() == "README.md" {
			continue
		}
		p := filepath.Join(dir, f.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("knowledge: baca %s: %w", p, err)
		}
		e, err := ParseEntry(data)
		if err != nil {
			return fmt.Errorf("knowledge: %s: %w", p, err)
		}
		e.Path = p
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// Get mengambil satu entry berdasarkan id — dicari di seluruh direktori
// resmi knowledge base. Tidak ditemukan = ErrNotFound.
func (s *Store) Get(id string) (*Entry, error) {
	if !isSlug(id) {
		return nil, fmt.Errorf("knowledge: id %q tidak valid", id)
	}
	for _, dir := range s.scanDirs() {
		p := entryPath(dir, id)
		if data, err := os.ReadFile(p); err == nil {
			e, err := ParseEntry(data)
			if err != nil {
				return nil, fmt.Errorf("knowledge: %s: %w", p, err)
			}
			e.Path = p
			return e, nil
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("knowledge: baca %s: %w", p, err)
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrNotFound, id)
}

// SetState mengubah state entry dengan validasi transisi ketat (§23).
// Transisi ilegal = ErrInvalidTransition (fail-closed, tidak ada jalan
// pintas). Entry reviewed/trusted berpindah direktori sesuai pemetaan.
//
// Firewall (§20, §23): entry yang membawa penanda konten target
// (source "target-controlled" atau trust=untrusted) TIDAK PERNAH naik ke
// reviewed/trusted — lapisan kedua untuk file yang diletakkan manual di
// direktori knowledge (ingest sudah menolaknya di pintu masuk). Cek
// firewall didahulukan atas validasi transisi agar pesan error menunjukkan
// penyebab keamanannya, bukan sekadar transisi salah.
func (s *Store) SetState(id string, newState State) (*Entry, error) {
	e, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if err := s.setStateFile(e, newState); err != nil {
		return nil, err
	}
	return e, nil
}

// setStateFile menerapkan transisi state pada SATU entry (hasil scan/Get,
// dengan e.Path terisi).
func (s *Store) setStateFile(e *Entry, newState State) error {
	if e.State == newState {
		return fmt.Errorf("%w: %s sudah berada di state %q", ErrInvalidTransition, e.ID, newState)
	}
	// Firewall dulu (§20, §23): konten target tidak boleh mencapai state
	// ber-review apapun kondisi transisinya.
	if e.isTargetControlled() {
		switch newState {
		case StateReviewed, StateTrusted:
			return fmt.Errorf("%w: konten target-controlled (id %s) tidak boleh dipromosikan ke %q — target-controlled content tidak pernah menjadi knowledge base (§20, §23)", ErrFirewall, e.ID, newState)
		}
	}
	if !CanTransition(e.State, newState) {
		return fmt.Errorf("%w: %s tidak boleh %s -> %s", ErrInvalidTransition, e.ID, e.State, newState)
	}
	// Re-review manusia (menuju reviewed) memperbarui last_reviewed —
	// dasar perhitungan staleness berikutnya.
	if newState == StateReviewed || newState == StateTrusted {
		e.LastReviewed = time.Now().UTC()
	}
	e.State = newState
	if newState == StateStale || newState == StateArchived {
		// stale/archived tidak memindahkan file; cukup frontmatter.
		return s.writeFileAt(e)
	}
	dst := s.knowledgeDir(newState)
	// Bila tujuan = file sumber (mis. re-review stale -> reviewed pada
	// entry yang sudah berada di reviewed/): tulis ulang di tempat, bukan
	// tulis-baru-then-hapus (writeEntry menolak tujuan yang sudah ada).
	if e.Path != "" && filepath.Clean(e.Path) == filepath.Clean(entryPath(dst, e.ID)) {
		return s.writeFileAt(e)
	}
	if err := s.writeEntry(e, dst); err != nil {
		return err
	}
	// Move semantics: hapus file lama agar tidak ada salinan bermata dua
	// (salinan lama akan membingungkan Get/Parse dengan state usang).
	if e.Path != "" && filepath.Clean(e.Path) != filepath.Clean(entryPath(dst, e.ID)) {
		if err := os.Remove(e.Path); err != nil {
			return fmt.Errorf("knowledge: hapus file lama %s: %w", e.Path, err)
		}
	}
	return nil
}

// writeFileAt menulis ulang entry ke file sumbernya (e.Path wajib terisi —
// entry hasil scan/Get). Bila Path kosong, file dicari berdasarkan id.
func (s *Store) writeFileAt(e *Entry) error {
	if e.Path == "" {
		if old := s.findEntryFile(e.ID); old != "" {
			e.Path = old
		} else {
			return fmt.Errorf("%w: file entry %s tidak ditemukan untuk ditulis ulang", ErrNotFound, e.ID)
		}
	}
	data, err := renderEntry(e)
	if err != nil {
		return err
	}
	if err := os.WriteFile(e.Path, data, 0o644); err != nil {
		return fmt.Errorf("knowledge: tulis %s: %w", e.Path, err)
	}
	return nil
}

// findEntryFile mencari path file entry berdasarkan id di direktori resmi
// knowledge base. "" bila tidak ketemu.
func (s *Store) findEntryFile(id string) string {
	for _, dir := range s.scanDirs() {
		p := entryPath(dir, id)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// MarkStale menandai entry yang last_reviewed-nya lebih tua dari 90 hari
// menjadi state=stale (§61 stale detection). Mengembalikan id yang ditandai.
func (s *Store) MarkStale(now time.Time) ([]string, error) {
	var all []*Entry
	for _, dir := range s.scanDirs() {
		if err := scanEntries(dir, func(e *Entry) error {
			all = append(all, e)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	var marked []string
	for _, e := range all {
		if e.State == StateStale || e.State == StateArchived {
			continue
		}
		if now.Sub(e.LastReviewed) <= staleAfter {
			continue
		}
		if err := s.setStateFile(e, StateStale); err != nil {
			return nil, fmt.Errorf("knowledge: tandai stale %s: %w", e.ID, err)
		}
		marked = append(marked, e.ID)
	}
	sort.Strings(marked)
	return marked, nil
}
