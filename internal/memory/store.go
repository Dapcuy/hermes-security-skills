package memory

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
	// ErrNotFound: entry/case tidak ditemukan di store.
	ErrNotFound = errors.New("memory: tidak ditemukan")
	// ErrInvalidTransition: transisi state tidak valid (fail-closed, §27).
	ErrInvalidTransition = errors.New("memory: transisi state tidak valid")
	// ErrFirewall: pelanggaran knowledge firewall (§24) — konten target
	// mencoba masuk ke jalur yang dilarang.
	ErrFirewall = errors.New("memory: knowledge firewall (§24) menolak operasi")
)

// Store adalah pipeline knowledge & memory di atas filesystem (§27):
//
//	<knowledge>/          — knowledge base (canonical/proposed/reviewed)
//	<cases>/              — case memory per engagement (memory/cases/<caseID>)
//
// Pemetaan state → direktori knowledge:
//
//	captured|normalized|proposed → <knowledge>/proposed/
//	reviewed                     → <knowledge>/reviewed/
//	trusted                      → <knowledge>/canonical/
//	stale|archived               → tetap di direktori semula (frontmatter saja)
type Store struct {
	Knowledge string // root direktori knowledge
	Cases     string // root direktori case memory (memory/cases)
}

// NewStore membangun Store dari root knowledge dan root memory.
// Case memory selalu berada di <memoryRoot>/cases (§27).
func NewStore(knowledgeRoot, memoryRoot string) *Store {
	return &Store{
		Knowledge: knowledgeRoot,
		Cases:     filepath.Join(memoryRoot, "cases"),
	}
}

// knowledgeDir menentukan direktori tujuan untuk entry dengan state tertentu.
func (s *Store) knowledgeDir(st State) string {
	switch st {
	case StateReviewed:
		return filepath.Join(s.Knowledge, "reviewed")
	case StateTrusted:
		return filepath.Join(s.Knowledge, "canonical")
	default:
		// captured, normalized, proposed (dan default konservatif).
		return filepath.Join(s.Knowledge, "proposed")
	}
}

// IngestMeta metadata ingest yang disediakan manusia (CLI).
type IngestMeta struct {
	Category   string     // wajib (bila kosong, pakai frontmatter)
	Source     string     // wajib (bila kosong, pakai frontmatter)
	Confidence *float64   // nil = pakai frontmatter
	ExpiresAt  *time.Time // opsional
}

// Ingest memvalidasi file entry lalu memindahkannya ke knowledge/proposed/
// (§41 knowledge ingestion). State hasil ingest dibatasi captured|normalized|
// proposed — reviewed/trusted TIDAK boleh dicapai lewat ingest agar tetap
// melewati human review (§27 proposed-to-reviewed lifecycle).
//
// Firewall (§24): file dengan provenance trust=untrusted DITOLAK — konten
// target hanya boleh masuk melalui IngestFromTarget ke memory/cases.
func (s *Store) Ingest(path string, meta IngestMeta) (*Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("memory: baca %s: %w", path, err)
	}
	e, err := ParseEntry(data)
	if err != nil {
		return nil, fmt.Errorf("memory: %s: %w", path, err)
	}
	// id opsional di frontmatter: turunkan dari nama file bila kosong.
	if e.ID == "" {
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		e.ID = Slugify(base)
	}
	if !isSlug(e.ID) {
		return nil, fmt.Errorf("memory: %s: id turunan %q tidak valid", path, e.ID)
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
		return nil, fmt.Errorf("memory: %s: confidence wajib ada (frontmatter atau --confidence)", path)
	}
	if meta.ExpiresAt != nil {
		t := meta.ExpiresAt.UTC()
		e.ExpiresAt = &t
	}
	if err := e.validate(); err != nil {
		return nil, fmt.Errorf("memory: %s: %w", path, err)
	}
	// Knowledge firewall (§24): entry untrusted tidak boleh masuk knowledge
	// base lewat jalur ingest manusia sekalipun — jalurnya memang tidak ada.
	if e.Provenance.Trust == TrustUntrusted {
		return nil, fmt.Errorf("%w: entry %s berasal dari target (trust=untrusted) dan tidak boleh masuk knowledge base — gunakan jalur case memory", ErrFirewall, e.ID)
	}
	// Human-in-the-loop: ingest hanya boleh menghasilkan state pra-review.
	switch e.State {
	case "", StateCaptured, StateNormalized, StateProposed:
		// Setelah tervalidasi, entry masuk pipeline sebagai proposed.
		e.State = StateProposed
	default:
		return nil, fmt.Errorf("memory: %s: ingest tidak boleh menetapkan state %q (hanya captured|normalized|proposed; reviewed/trusted lewat review manusia, §27)", path, e.State)
	}
	if e.LastReviewed.IsZero() {
		e.LastReviewed = time.Now().UTC()
	}
	if err := s.writeEntry(e, s.knowledgeDir(e.State)); err != nil {
		return nil, err
	}
	// Move semantics: hapus file sumber bila berbeda dari tujuan.
	srcAbs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dstAbs, err := filepath.Abs(entryPath(s.knowledgeDir(e.State), e.ID))
	if err != nil {
		return nil, err
	}
	if srcAbs != dstAbs {
		if err := os.Remove(srcAbs); err != nil {
			return nil, fmt.Errorf("memory: hapus sumber %s: %w", path, err)
		}
	}
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
		return fmt.Errorf("memory: id %q tidak valid", e.ID)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("memory: buat direktori %s: %w", dir, err)
	}
	dst := entryPath(dir, e.ID)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("memory: entry %s sudah ada di %s (tidak menimpa)", e.ID, dst)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("memory: cek %s: %w", dst, err)
	}
	data, err := renderEntry(e)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("memory: tulis %s: %w", dst, err)
	}
	return nil
}

// Filter penyaring List (string kosong = tanpa filter).
type Filter struct {
	State    State
	Category string
}

// List mengembalikan semua entry (knowledge + case memory) yang lolos filter,
// terurut by id (deterministik). Entry tidak parseable = error fail-closed.
func (s *Store) List(f Filter) ([]*Entry, error) {
	var out []*Entry
	seen := map[string]bool{}
	for _, dir := range s.knowledgeScanDirs() {
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
	// Case memory: memory/cases/<caseID>/<id>.md (satu level case).
	caseEntries, err := s.scanCases()
	if err != nil {
		return nil, err
	}
	for _, e := range caseEntries {
		if !seen[e.ID] {
			seen[e.ID] = true
			out = append(out, e)
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

// knowledgeScanDirs: direktori knowledge yang di-scan (canonical, proposed,
// reviewed). Direktori tak ada = diabaikan (store baru yang masih kosong).
func (s *Store) knowledgeScanDirs() []string {
	return []string{
		filepath.Join(s.Knowledge, "canonical"),
		filepath.Join(s.Knowledge, "proposed"),
		filepath.Join(s.Knowledge, "reviewed"),
	}
}

// scanCases membaca semua entry case memory di <Cases>/<caseID>/*.md.
func (s *Store) scanCases() ([]*Entry, error) {
	var out []*Entry
	entries, err := os.ReadDir(s.Cases)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("memory: baca %s: %w", s.Cases, err)
	}
	for _, c := range entries {
		if !c.IsDir() {
			continue // <caseID>.archived dsb. dilewati
		}
		dir := filepath.Join(s.Cases, c.Name())
		if err := scanEntries(dir, func(e *Entry) error {
			out = append(out, e)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// scanEntries mem-parse semua *.md pada satu direktori (non-rekursif).
func scanEntries(dir string, fn func(*Entry) error) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("memory: baca %s: %w", dir, err)
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
			continue
		}
		p := filepath.Join(dir, f.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("memory: baca %s: %w", p, err)
		}
		e, err := ParseEntry(data)
		if err != nil {
			return fmt.Errorf("memory: %s: %w", p, err)
		}
		e.Path = p
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// Get mengambil satu entry berdasarkan id — dicari di direktori knowledge
// lalu di semua case. Tidak ditemukan = ErrNotFound.
func (s *Store) Get(id string) (*Entry, error) {
	if !isSlug(id) {
		return nil, fmt.Errorf("memory: id %q tidak valid", id)
	}
	for _, dir := range s.knowledgeScanDirs() {
		p := entryPath(dir, id)
		if data, err := os.ReadFile(p); err == nil {
			e, err := ParseEntry(data)
			if err != nil {
				return nil, fmt.Errorf("memory: %s: %w", p, err)
			}
			e.Path = p
			return e, nil
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("memory: baca %s: %w", p, err)
		}
	}
	// Cari di case memory (path <Cases>/<case>/<id>.md).
	caseEntries, err := s.scanCases()
	if err != nil {
		return nil, err
	}
	for _, e := range caseEntries {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrNotFound, id)
}

// SetState mengubah state entry dengan validasi transisi ketat (§27).
// Transisi ilegal = ErrInvalidTransition (fail-closed, tidak ada jalan
// pintas). Entry reviewed/trusted berpindah direktori sesuai pemetaan.
//
// Firewall (§24): entry trust=untrusted TIDAK PERNAH boleh naik ke
// reviewed/trusted — konten target tidak pernah menulis canonical knowledge.
// Cek firewall didahulukan atas validasi transisi agar pesan error
// menunjukkan penyebab keamanannya, bukan sekadar transisi salah.
func (s *Store) SetState(id string, newState State) (*Entry, error) {
	e, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if e.State == newState {
		return nil, fmt.Errorf("%w: %s sudah berada di state %q", ErrInvalidTransition, id, newState)
	}
	// Firewall dulu (§24): konten target tidak boleh mencapai knowledge
	// base ber-review apapun kondisi transisinya.
	if e.Provenance.Trust == TrustUntrusted {
		switch newState {
		case StateReviewed, StateTrusted:
			return nil, fmt.Errorf("%w: konten target-controlled (id %s) tidak boleh dipromosikan ke %q — hanya boleh sampai di case memory (§24)", ErrFirewall, id, newState)
		}
	}
	if !CanTransition(e.State, newState) {
		return nil, fmt.Errorf("%w: %s tidak boleh %s -> %s", ErrInvalidTransition, id, e.State, newState)
	}
	// Re-review manusia (menuju reviewed) memperbarui last_reviewed —
	// dasar perhitungan staleness berikutnya.
	if newState == StateReviewed || newState == StateTrusted {
		e.LastReviewed = time.Now().UTC()
	}
	e.State = newState
	if newState == StateStale || newState == StateArchived {
		// stale/archived tidak memindahkan file; cukup frontmatter.
		if err := s.rewriteInPlace(e); err != nil {
			return nil, err
		}
		return e, nil
	}
	dst := s.knowledgeDir(newState)
	old := s.findEntryFile(e.ID)
	// Konten target (untrusted) SELALU tinggal di case memory — transisi
	// state apapun tidak boleh memindahkannya ke direktori knowledge (§24).
	if e.Provenance.Trust == TrustUntrusted {
		if err := s.rewriteInPlace(e); err != nil {
			return nil, err
		}
		return e, nil
	}
	if err := s.writeEntry(e, dst); err != nil {
		return nil, err
	}
	// Move semantics: hapus file lama agar tidak ada salinan bermata dua
	// (salinan lama akan membingungkan Get/Parse dengan state usang).
	if old != "" && filepath.Clean(old) != filepath.Clean(entryPath(dst, e.ID)) {
		if err := os.Remove(old); err != nil {
			return nil, fmt.Errorf("memory: hapus file lama %s: %w", old, err)
		}
	}
	return e, nil
}

// rewriteInPlace menimpa file entry yang sudah ada dengan state baru.
// Aman karena file itu sendiri adalah tempat state disimpan (append-only
// tidak berlaku untuk file entry; audit trail ada di audit log).
func (s *Store) rewriteInPlace(e *Entry) error {
	old := s.findEntryFile(e.ID)
	if old == "" {
		return fmt.Errorf("%w: file entry %s tidak ditemukan untuk ditulis ulang", ErrNotFound, e.ID)
	}
	data, err := renderEntry(e)
	if err != nil {
		return err
	}
	if err := os.WriteFile(old, data, 0o644); err != nil {
		return fmt.Errorf("memory: tulis %s: %w", old, err)
	}
	return nil
}

// findEntryFile mencari path file entry berdasarkan id (knowledge dulu,
// lalu case memory). "" bila tidak ketemu.
func (s *Store) findEntryFile(id string) string {
	for _, dir := range s.knowledgeScanDirs() {
		p := entryPath(dir, id)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, c := range s.caseDirs() {
		p := entryPath(c, id)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// caseDirs: direktori case aktif (bukan .archived) yang ada saat ini.
func (s *Store) caseDirs() []string {
	entries, err := os.ReadDir(s.Cases)
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range entries {
		if c.IsDir() {
			out = append(out, filepath.Join(s.Cases, c.Name()))
		}
	}
	return out
}

// MarkStale menandai entry yang last_reviewed-nya lebih tua dari 90 hari
// menjadi state=stale (§41 stale knowledge detection). Mengembalikan id
// yang ditandai. Entry untrusted di case memory ikut dievaluasi.
func (s *Store) MarkStale(now time.Time) ([]string, error) {
	all, err := s.List(Filter{})
	if err != nil {
		return nil, err
	}
	var marked []string
	for _, e := range all {
		if e.State == StateStale || e.State == StateArchived {
			continue
		}
		if now.Sub(e.LastReviewed) <= staleAfter {
			continue
		}
		if _, err := s.SetState(e.ID, StateStale); err != nil {
			return nil, fmt.Errorf("memory: tandai stale %s: %w", e.ID, err)
		}
		marked = append(marked, e.ID)
	}
	sort.Strings(marked)
	return marked, nil
}

// RetentionResult ringkasan eksekusi retention satu case (§25).
type RetentionResult struct {
	CaseID          string
	ArchivedEntries []string // id entry yang mencapai state=archived
	Remaining       []string // id entry yang belum expired
	CaseArchived    bool     // direktori case dipindah ke <caseID>.archived
	ArchivedPath    string   // path hasil arsip (bila CaseArchived)
}

// Retention memproses retention policy satu case (§25):
//
//  1. entry memory/cases/<caseID> dengan expires_at yang sudah lewat
//     di-set state=archived (transisi dari state apapun kecuali archived);
//  2. bila SEMUA entry case sudah archived, direktori case diarsipkan
//     utuh menjadi memory/cases/<caseID>.archived — data tidak lagi aktif.
//
// Entry tanpa expires_at tidak pernah expired (tetap Remaining) — pembuat
// entry wajib menetapkan expires_at (IngestFromTarget menolak tanpa itu).
func (s *Store) Retention(caseID string, now time.Time) (*RetentionResult, error) {
	if !isSlug(caseID) {
		return nil, fmt.Errorf("memory: case id %q tidak valid", caseID)
	}
	dir := filepath.Join(s.Cases, caseID)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: case %q (tidak ada %s)", ErrNotFound, caseID, dir)
	}
	res := &RetentionResult{CaseID: caseID}
	// Hanya scan direktori case yang diminta — id di case lain tidak boleh
	// ikut terproses (case isolation, §27).
	var entries []*Entry
	if err := scanEntries(dir, func(e *Entry) error {
		entries = append(entries, e)
		return nil
	}); err != nil {
		return nil, err
	}
	for _, e := range entries {
		expired := e.ExpiresAt != nil && now.After(*e.ExpiresAt)
		switch {
		case e.State == StateArchived:
			res.ArchivedEntries = append(res.ArchivedEntries, e.ID)
		case expired:
			// Force arsip: transisi *→archived valid untuk semua state
			// pra-arsip; lewat SetState agar tetap satu jalur validasi.
			if _, err := s.SetState(e.ID, StateArchived); err != nil {
				return nil, fmt.Errorf("memory: arsip entry %s: %w", e.ID, err)
			}
			res.ArchivedEntries = append(res.ArchivedEntries, e.ID)
		default:
			res.Remaining = append(res.Remaining, e.ID)
		}
	}
	sort.Strings(res.ArchivedEntries)
	sort.Strings(res.Remaining)
	// Semua entry sudah archived (dan ada minimal satu) → arsipkan direktori.
	if len(res.ArchivedEntries) > 0 && len(res.Remaining) == 0 {
		dst := filepath.Join(s.Cases, caseID+".archived")
		if _, err := os.Stat(dst); err == nil {
			return nil, fmt.Errorf("memory: arsip %s sudah ada (tidak menimpa)", dst)
		}
		if err := os.MkdirAll(s.Cases, 0o755); err != nil {
			return nil, err
		}
		if err := os.Rename(dir, dst); err != nil {
			return nil, fmt.Errorf("memory: arsip case %s: %w", caseID, err)
		}
		res.CaseArchived = true
		res.ArchivedPath = dst
	}
	return res, nil
}

// TargetIngest parameter wajib IngestFromTarget.
type TargetIngest struct {
	CaseID    string    // case engagement asal (wajib)
	Category  string    // kategori observasi, mis. "observation" (wajib)
	Title     string    // judul entry (wajib)
	ExpiresAt time.Time // WAJIB — tidak ada data target persist tanpa batas (§25)
}

// IngestFromTarget adalah SATU-SATUNYA jalur masuk konten target ke memory
// (knowledge firewall, §24):
//
//   - konten selalu menjadi entry state=captured di memory/cases/<caseID>/;
//   - provenance dipaksa {source: "target-controlled", trust: untrusted} —
//     pemanggil tidak bisa menggantinya;
//   - knowledge/canonical TIDAK pernah disentuh (diverifikasi test);
//   - expires_at wajib (tidak ada data target persist tanpa batas, §25).
//
// Body disimpan apa adanya sebagai DATA terkutip — tidak pernah dieksekusi
// atau memengaruhi policy (§24 prinsip).
func (s *Store) IngestFromTarget(text string, in TargetIngest) (*Entry, error) {
	if !isSlug(in.CaseID) {
		return nil, fmt.Errorf("%w: case id %q tidak valid", ErrFirewall, in.CaseID)
	}
	if strings.TrimSpace(in.Category) == "" || strings.TrimSpace(in.Title) == "" {
		return nil, fmt.Errorf("%w: category dan title wajib untuk konten target", ErrFirewall)
	}
	if in.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: expires_at wajib — tidak ada data target persist tanpa batas waktu (§25)", ErrFirewall)
	}
	e := &Entry{
		ID:         "",
		Title:      in.Title,
		Category:   strings.TrimSpace(in.Category),
		Source:     SourceTargetControlled,
		Provenance: Provenance{Source: SourceTargetControlled, Trust: TrustUntrusted},
		Confidence: 0, // konten target tidak diberi confidence oleh sistem
		State:      StateCaptured,
		Body:       text,
		ExpiresAt:  func() *time.Time { t := in.ExpiresAt.UTC(); return &t }(),
	}
	e.LastReviewed = time.Now().UTC()
	dir := filepath.Join(s.Cases, in.CaseID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("memory: buat case dir %s: %w", dir, err)
	}
	// id unik dalam case: slug(title), lalu -2, -3, ... bila bentrok.
	base := Slugify(in.Title)
	if base == "" {
		base = "target-entry"
	}
	for attempt := 1; attempt <= 100; attempt++ {
		id := base
		if attempt > 1 {
			id = fmt.Sprintf("%s-%d", base, attempt)
		}
		e.ID = id
		if _, err := os.Stat(entryPath(dir, id)); os.IsNotExist(err) {
			break
		}
		if attempt == 100 {
			return nil, fmt.Errorf("memory: tidak bisa menemukan id unik untuk %q di case %s", in.Title, in.CaseID)
		}
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	// Tulis langsung (bukan writeEntry yang menolak existing — id sudah
	// dipastikan unik di atas).
	data, err := renderEntry(e)
	if err != nil {
		return nil, err
	}
	p := entryPath(dir, e.ID)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return nil, fmt.Errorf("memory: tulis %s: %w", p, err)
	}
	e.Path = p
	return e, nil
}
