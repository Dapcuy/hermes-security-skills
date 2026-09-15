package knowledge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newTestStore membuat store kosong di temp dir.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "knowledge"))
}

// writeRaw menulis file markdown mentah ke path.
func writeRaw(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("tulis %s: %v", path, err)
	}
}

// writeEntry menulis Entry via renderEntry ke path.
func writeEntry(t *testing.T, path string, e *Entry) {
	t.Helper()
	data, err := renderEntry(e)
	if err != nil {
		t.Fatalf("renderEntry: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("tulis %s: %v", path, err)
	}
}

func sampleEntry(id string) *Entry {
	return &Entry{
		ID:           id,
		Title:        "Reflected XSS in search parameter",
		Category:     "xss-analysis",
		Source:       "manual-research",
		Provenance:   Provenance{Source: "manual", Trust: TrustTrusted},
		Confidence:   0.8,
		State:        StateProposed,
		LastReviewed: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Body:         "# Catatan\n\nBody markdown dengan kata xss reflection.",
	}
}

// ---------------------------------------------------------------- parse

func TestParseEntryRoundTrip(t *testing.T) {
	e := sampleEntry("xss-reflected-note")
	data, err := renderEntry(e)
	if err != nil {
		t.Fatalf("renderEntry: %v", err)
	}
	got, err := ParseEntry(data)
	if err != nil {
		t.Fatalf("ParseEntry: %v\n---\n%s", err, data)
	}
	if got.ID != e.ID || got.Title != e.Title || got.Category != e.Category ||
		got.Source != e.Source || got.State != e.State {
		t.Errorf("round-trip field mismatch: %+v", got)
	}
	if got.Confidence != e.Confidence {
		t.Errorf("confidence = %v, mau %v", got.Confidence, e.Confidence)
	}
	if got.Provenance != e.Provenance {
		t.Errorf("provenance = %+v, mau %+v", got.Provenance, e.Provenance)
	}
	if !got.LastReviewed.Equal(e.LastReviewed) {
		t.Errorf("last_reviewed = %v, mau %v", got.LastReviewed, e.LastReviewed)
	}
	if !strings.Contains(got.Body, "reflection") {
		t.Errorf("body hilang: %q", got.Body)
	}
}

func TestParseEntryFailClosed(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"tanpa frontmatter", "hanya body markdown"},
		{"frontmatter tak ditutup", "---\nid: x\n"},
		{"id tidak valid", "---\nid: ../evil\ntitle: t\ncategory: c\nsource: s\nconfidence: 0.5\nstate: proposed\nlast_reviewed: 2026-09-01T00:00:00Z\nprovenance:\n  source: m\n  trust: trusted\n---\nbody"},
		{"confidence di luar rentang", "---\nid: x\ntitle: t\ncategory: c\nsource: s\nconfidence: 1.5\nstate: proposed\nlast_reviewed: 2026-09-01T00:00:00Z\nprovenance:\n  source: m\n  trust: trusted\n---\nbody"},
		{"state tidak dikenal", "---\nid: x\ntitle: t\ncategory: c\nsource: s\nconfidence: 0.5\nstate: super-trusted\nlast_reviewed: 2026-09-01T00:00:00Z\nprovenance:\n  source: m\n  trust: trusted\n---\nbody"},
		{"trust tidak dikenal", "---\nid: x\ntitle: t\ncategory: c\nsource: s\nconfidence: 0.5\nstate: proposed\nlast_reviewed: 2026-09-01T00:00:00Z\nprovenance:\n  source: m\n  trust: maybe\n---\nbody"},
		{"last_reviewed bukan RFC3339", "---\nid: x\ntitle: t\ncategory: c\nsource: s\nconfidence: 0.5\nstate: proposed\nlast_reviewed: kemarin\nprovenance:\n  source: m\n  trust: trusted\n---\nbody"},
		{"provenance bukan map", "---\nid: x\ntitle: t\ncategory: c\nsource: s\nconfidence: 0.5\nstate: proposed\nlast_reviewed: 2026-09-01T00:00:00Z\nprovenance: manual\n---\nbody"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseEntry([]byte(tc.src)); err == nil {
				t.Errorf("harus error (fail-closed)")
			}
		})
	}
}

// ---------------------------------------------------------------- transitions

func TestCanTransition(t *testing.T) {
	valid := [][2]State{
		{StateCaptured, StateNormalized}, {StateNormalized, StateProposed},
		{StateProposed, StateReviewed}, {StateReviewed, StateTrusted},
		{StateCaptured, StateStale}, {StateProposed, StateStale},
		{StateTrusted, StateStale}, {StateStale, StateReviewed},
		{StateCaptured, StateArchived}, {StateTrusted, StateArchived},
		{StateStale, StateArchived},
	}
	for _, tr := range valid {
		if !CanTransition(tr[0], tr[1]) {
			t.Errorf("transisi %s -> %s harus valid", tr[0], tr[1])
		}
	}
	invalid := [][2]State{
		{StateCaptured, StateReviewed}, // lompat review (§23)
		{StateCaptured, StateTrusted},
		{StateProposed, StateCaptured}, // mundur
		{StateTrusted, StateReviewed},  // mundur
		{StateArchived, StateReviewed}, // archived terminal
		{StateArchived, StateStale},
		{State("aneh"), StateProposed},
		{StateProposed, State("aneh")},
	}
	for _, tr := range invalid {
		if CanTransition(tr[0], tr[1]) {
			t.Errorf("transisi %s -> %s harus DITOLAK", tr[0], tr[1])
		}
	}
}

func TestSetStateLifecycle(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Ingest(writeIngestFile(t, sampleEntry("")), IngestMeta{}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// captured-chain via ingest langsung jadi proposed; lanjut review.
	for _, step := range []State{StateReviewed, StateTrusted, StateStale, StateArchived} {
		e, err := s.SetState("xss-reflected-note", step)
		if err != nil {
			t.Fatalf("SetState -> %s: %v", step, err)
		}
		if e.State != step {
			t.Errorf("state = %s, mau %s", e.State, step)
		}
	}
	// archived terminal: transisi lanjutan ditolak.
	if _, err := s.SetState("xss-reflected-note", StateReviewed); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("transisi dari archived harus ditolak, dapat: %v", err)
	}
}

func TestSetStateInvalidTransitionFailClosed(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Ingest(writeIngestFile(t, sampleEntry("")), IngestMeta{}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// proposed -> captured = mundur, harus ditolak.
	if _, err := s.SetState("xss-reflected-note", StateCaptured); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("proposed->captured harus ditolak, dapat: %v", err)
	}
	// id tidak ada.
	if _, err := s.SetState("tidak-ada", StateReviewed); !errors.Is(err, ErrNotFound) {
		t.Errorf("id tidak dikenal harus ErrNotFound, dapat: %v", err)
	}
}

func TestSetStateMovesDirectories(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Ingest(writeIngestFile(t, sampleEntry("")), IngestMeta{}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// §23: hasil ingest (proposed) hidup di research/.
	research := filepath.Join(s.Root, "research", "xss-reflected-note.md")
	if _, err := os.Stat(research); err != nil {
		t.Fatalf("entry harus ada di research: %v", err)
	}
	if _, err := s.SetState("xss-reflected-note", StateReviewed); err != nil {
		t.Fatalf("SetState reviewed: %v", err)
	}
	if _, err := os.Stat(research); !os.IsNotExist(err) {
		t.Errorf("file lama di research harus terhapus, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Root, "reviewed", "xss-reflected-note.md")); err != nil {
		t.Fatalf("entry harus pindah ke reviewed: %v", err)
	}
	// §23: promosi ke canonical adalah keputusan owner — SetState reviewed
	// -> trusted menulis ke canonical/.
	if _, err := s.SetState("xss-reflected-note", StateTrusted); err != nil {
		t.Fatalf("SetState trusted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Root, "canonical", "xss-reflected-note.md")); err != nil {
		t.Fatalf("entry harus masuk canonical: %v", err)
	}
}

func TestSetStateStaleStaysInPlace(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Ingest(writeIngestFile(t, sampleEntry("")), IngestMeta{}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if _, err := s.SetState("xss-reflected-note", StateStale); err != nil {
		t.Fatalf("SetState stale: %v", err)
	}
	p := filepath.Join(s.Root, "research", "xss-reflected-note.md")
	e, err := ParseEntry(mustRead(t, p))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.State != StateStale {
		t.Errorf("state = %s, mau stale", e.State)
	}
}

// ---------------------------------------------------------------- ingest

func TestIngestMovesToResearch(t *testing.T) {
	s := newTestStore(t)
	src := writeIngestFile(t, sampleEntry(""))
	e, err := s.Ingest(src, IngestMeta{})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if e.State != StateProposed {
		t.Errorf("state = %s, mau proposed", e.State)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("file sumber harus terhapus (move), err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Root, "research", e.ID+".md")); err != nil {
		t.Errorf("entry harus ada di knowledge/research: %v", err)
	}
}

func TestIngestMetaOverrides(t *testing.T) {
	s := newTestStore(t)
	src := writeIngestFile(t, sampleEntry(""))
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	conf := 0.55
	e, err := s.Ingest(src, IngestMeta{Category: "idor-and-bola", Source: "report-draft", Confidence: &conf, ExpiresAt: &exp})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if e.Category != "idor-and-bola" || e.Source != "report-draft" || e.Confidence != 0.55 {
		t.Errorf("override tidak diterapkan: %+v", e)
	}
	if e.ExpiresAt == nil || !e.ExpiresAt.Equal(exp) {
		t.Errorf("expires_at = %v, mau %v", e.ExpiresAt, exp)
	}
}

func TestIngestDuplicateFailsClosed(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Ingest(writeIngestFile(t, sampleEntry("")), IngestMeta{}); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	// File kedua dengan id sama (di frontmatter) harus ditolak.
	if _, err := s.Ingest(writeIngestFile(t, sampleEntry("xss-reflected-note")), IngestMeta{}); err == nil {
		t.Errorf("ingest duplikat harus gagal (tidak menimpa)")
	}
}

// ---------------------------------------------------------------- list/get

func TestListAndGet(t *testing.T) {
	s := newTestStore(t)
	a := sampleEntry("")
	a.ID = "entry-alpha"
	b := sampleEntry("")
	b.ID = "entry-beta"
	b.Category = "idor-and-bola"
	b.State = StateCaptured
	if _, err := s.Ingest(writeIngestFile(t, a), IngestMeta{}); err != nil {
		t.Fatal(err)
	}
	// entry-beta ditulis langsung sebagai captured di research dir.
	writeEntry(t, filepath.Join(s.Root, "research", "entry-beta.md"), b)
	// entry-gamma: curated manual di methodology/ ikut ter-scan (§23).
	g := sampleEntry("")
	g.ID = "entry-gamma"
	g.Category = "injection-analysis"
	writeEntry(t, filepath.Join(s.Root, "methodology", "entry-gamma.md"), g)

	all, err := s.List(Filter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("list = %d entry, mau 3: %+v", len(all), all)
	}
	if all[0].ID != "entry-alpha" || all[1].ID != "entry-beta" || all[2].ID != "entry-gamma" {
		t.Errorf("urutan salah: %s, %s, %s", all[0].ID, all[1].ID, all[2].ID)
	}
	// Filter state.
	onlyCaptured, err := s.List(Filter{State: StateCaptured})
	if err != nil {
		t.Fatal(err)
	}
	if len(onlyCaptured) != 1 || onlyCaptured[0].ID != "entry-beta" {
		t.Errorf("filter state salah: %+v", onlyCaptured)
	}
	// Filter category (case-insensitive).
	onlyIDOR, err := s.List(Filter{Category: "IDOR-AND-BOLA"})
	if err != nil {
		t.Fatal(err)
	}
	if len(onlyIDOR) != 1 || onlyIDOR[0].ID != "entry-beta" {
		t.Errorf("filter category salah: %+v", onlyIDOR)
	}
	// Get dari direktori curated manual.
	e, err := s.Get("entry-gamma")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if e.Title != g.Title {
		t.Errorf("get field salah")
	}
	if _, err := s.Get("tidak-ada"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get tidak ada harus ErrNotFound, dapat: %v", err)
	}
	// Anti path traversal: id dengan separator ditolak.
	if _, err := s.Get("../evil"); err == nil {
		t.Errorf("id traversal harus ditolak")
	}
}

// ---------------------------------------------------------------- search

func TestSearchInvertedIndex(t *testing.T) {
	s := newTestStore(t)
	a := sampleEntry("")
	a.ID = "xss-note"
	a.Body = "Body dengan kata reflection dua kali: reflection dan lagi reflection."
	if _, err := s.Ingest(writeIngestFile(t, a), IngestMeta{}); err != nil {
		t.Fatal(err)
	}
	b := sampleEntry("")
	b.ID = "idor-note"
	b.Title = "IDOR on orders endpoint"
	b.Category = "idor-and-bola"
	b.Body = "Objek orders dapat diakses lintas akun. Reflection hanya satu kali di sini."
	if _, err := s.Ingest(writeIngestFile(t, b), IngestMeta{}); err != nil {
		t.Fatal(err)
	}
	// Kecocokan satu token di beberapa entry — skor frekuensi menentukan.
	res, err := s.Search("reflection")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("search 'reflection' = %d hasil, mau 2 (body keduanya memuat kata itu)", len(res))
	}
	if res[0].Entry.ID != "xss-note" {
		t.Errorf("skor tertinggi = %s, mau xss-note (frekuensi lebih tinggi)", res[0].Entry.ID)
	}
	// Multi-token.
	res, err = s.Search("idor orders")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res) == 0 || res[0].Entry.ID != "idor-note" {
		t.Errorf("search 'idor orders' salah: %+v", res)
	}
	// Query tidak cocok.
	res, err = s.Search("zzzzqqqq")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("query tanpa kecocokan harus kosong, dapat %d", len(res))
	}
	// Query kosong = error.
	if _, err := s.Search("  !!  "); err == nil {
		t.Errorf("query tanpa token harus error")
	}
}

// ---------------------------------------------------------------- stale

func TestMarkStale(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	fresh := sampleEntry("")
	fresh.ID = "entry-fresh"
	if _, err := s.Ingest(writeIngestFile(t, fresh), IngestMeta{}); err != nil {
		t.Fatal(err)
	}
	old := sampleEntry("")
	old.ID = "entry-old"
	old.LastReviewed = now.Add(-91 * 24 * time.Hour) // > 90 hari
	writeEntry(t, filepath.Join(s.Root, "reviewed", "entry-old.md"), old)
	edge := sampleEntry("")
	edge.ID = "entry-edge"
	edge.LastReviewed = now.Add(-90 * 24 * time.Hour) // tepat 90 hari = belum stale
	writeEntry(t, filepath.Join(s.Root, "reviewed", "entry-edge.md"), edge)

	marked, err := s.MarkStale(now)
	if err != nil {
		t.Fatalf("MarkStale: %v", err)
	}
	if len(marked) != 1 || marked[0] != "entry-old" {
		t.Errorf("marked = %v, mau [entry-old]", marked)
	}
	eOld, _ := s.Get("entry-old")
	if eOld.State != StateStale {
		t.Errorf("state entry-old = %s, mau stale", eOld.State)
	}
	eFresh, _ := s.Get("entry-fresh")
	if eFresh.State != StateProposed {
		t.Errorf("state entry-fresh = %s, mau proposed (tidak boleh ikut stale)", eFresh.State)
	}
	// Panggilan kedua: tidak ada yang baru ditandai.
	marked2, err := s.MarkStale(now)
	if err != nil || len(marked2) != 0 {
		t.Errorf("panggilan kedua marked = %v err=%v, mau kosong", marked2, err)
	}
	// stale -> reviewed (re-review manusia) memperbarui last_reviewed.
	if _, err := s.SetState("entry-old", StateReviewed); err != nil {
		t.Fatalf("re-review: %v", err)
	}
	eOld2, _ := s.Get("entry-old")
	if !eOld2.LastReviewed.After(time.Now().Add(-time.Hour)) {
		t.Errorf("last_reviewed harus diperbarui saat review, dapat %v", eOld2.LastReviewed)
	}
}

// ---------------------------------------------------------------- firewall §20/§23

// TestIngestRejectsTargetControlled: bukti inti knowledge firewall v3.0 —
// entry dengan provenance.source "target-controlled" (cap sistem konten
// target) DITOLAK fail-closed oleh Ingest; tidak ada jalur apapun yang
// menuliskannya ke knowledge base. Konten target hidup di evidence.
func TestIngestRejectsTargetControlled(t *testing.T) {
	s := newTestStore(t)
	// Vektor 1: cap target-controlled dengan trust ikut untrusted.
	e := sampleEntry("")
	e.ID = "evil-note"
	e.Provenance = Provenance{Source: SourceTargetControlled, Trust: TrustUntrusted}
	src := writeIngestFile(t, e)
	if _, err := s.Ingest(src, IngestMeta{}); !errors.Is(err, ErrFirewall) {
		t.Errorf("ingest entry target-controlled harus ErrFirewall, dapat: %v", err)
	}
	// Vektor 2 (THE BYPASS): trust dipalsukan trusted, cap
	// source=target-controlled DIPERTAHANKAN — tetap harus ditolak.
	e2 := sampleEntry("")
	e2.ID = "evil-note-2"
	e2.Provenance = Provenance{Source: SourceTargetControlled, Trust: TrustTrusted}
	src2 := writeIngestFile(t, e2)
	if _, err := s.Ingest(src2, IngestMeta{}); !errors.Is(err, ErrFirewall) {
		t.Errorf("ingest dengan cap target-controlled + trust palsu harus ErrFirewall, dapat: %v", err)
	}
	// Vektor 3: trust=untrusted dengan source bebas — tetap ditolak
	// (klaim untrusted = konten target, apa pun nama sumbernya).
	e3 := sampleEntry("")
	e3.ID = "evil-note-3"
	e3.Provenance = Provenance{Source: "some-response", Trust: TrustUntrusted}
	src3 := writeIngestFile(t, e3)
	if _, err := s.Ingest(src3, IngestMeta{}); !errors.Is(err, ErrFirewall) {
		t.Errorf("ingest entry trust=untrusted harus ErrFirewall, dapat: %v", err)
	}
	// File sumber tidak boleh terhapus saat ditolak.
	for _, p := range []string{src, src2, src3} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("file sumber %s harus tetap ada: %v", p, err)
		}
	}
	// Tidak ada file baru di direktori knowledge mana pun (§23).
	for _, d := range []string{"canonical", "research", "methodology", "false-positives", "reviewed"} {
		if files := listDir(t, filepath.Join(s.Root, d)); len(files) != 0 {
			t.Errorf("knowledge/%s harus kosong, dapat: %v", d, files)
		}
	}
}

func TestIngestRejectsTargetControlledCaseVariant(t *testing.T) {
	s := newTestStore(t)
	e := sampleEntry("")
	e.ID = "evil-case-variant"
	e.Provenance = Provenance{Source: "TARGET-CONTROLLED", Trust: TrustTrusted}
	src := writeIngestFile(t, e)
	if _, err := s.Ingest(src, IngestMeta{}); !errors.Is(err, ErrFirewall) {
		t.Errorf("case variant target-controlled harus ErrFirewall, dapat: %v", err)
	}
}

// TestSetStateRejectsUntrustedPromotion: lapisan kedua firewall — file
// untrusted yang diletakkan manual di direktori knowledge (bukan lewat
// Ingest) tidak boleh dipromosikan ke reviewed/trusted (§20, §23).
func TestSetStateRejectsUntrustedPromotion(t *testing.T) {
	s := newTestStore(t)
	e := sampleEntry("sneaky-note")
	e.Provenance = Provenance{Source: SourceTargetControlled, Trust: TrustUntrusted}
	e.State = StateProposed
	// Diletakkan manual di research/ (melewati Ingest).
	writeEntry(t, filepath.Join(s.Root, "research", "sneaky-note.md"), e)
	for _, target := range []State{StateReviewed, StateTrusted} {
		if _, err := s.SetState("sneaky-note", target); !errors.Is(err, ErrFirewall) {
			t.Errorf("promosi untrusted -> %s harus ErrFirewall, dapat: %v", target, err)
		}
	}
	// canonical tetap bersih.
	for _, d := range []string{"canonical", "reviewed"} {
		if files := listDir(t, filepath.Join(s.Root, d)); len(files) != 0 {
			t.Errorf("knowledge/%s harus tetap kosong, dapat: %v", d, files)
		}
	}
}

// ---------------------------------------------------------------- helpers

// writeIngestFile menulis file draf ingest: field yang justru diisi oleh
// Ingest (id, state, last_reviewed) sengaja tidak ditulis bila kosong —
// persis seperti file yang ditulis manusia. confidence ditulis bila > 0.
func writeIngestFile(t *testing.T, e *Entry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "xss-reflected-note.md")
	var b strings.Builder
	b.WriteString("---\n")
	if e.ID != "" {
		fmt.Fprintf(&b, "id: %s\n", e.ID)
	}
	fmt.Fprintf(&b, "title: %s\ncategory: %s\nsource: %s\n", e.Title, e.Category, e.Source)
	if e.Confidence > 0 {
		fmt.Fprintf(&b, "confidence: %s\n", strconv.FormatFloat(e.Confidence, 'f', -1, 64))
	}
	if !e.LastReviewed.IsZero() {
		fmt.Fprintf(&b, "last_reviewed: %s\n", e.LastReviewed.UTC().Format(time.RFC3339))
	}
	if e.ExpiresAt != nil {
		fmt.Fprintf(&b, "expires_at: %s\n", e.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if e.State != "" {
		fmt.Fprintf(&b, "state: %s\n", e.State)
	}
	fmt.Fprintf(&b, "provenance:\n  source: %s\n  trust: %s\n---\n\n%s\n",
		e.Provenance.Source, e.Provenance.Trust, e.Body)
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("tulis draft %s: %v", p, err)
	}
	return p
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("baca %s: %v", p, err)
	}
	return data
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("readDir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Reflected XSS in Search!": "reflected-xss-in-search",
		"  --weird__title..":       "weird-title",
		"Ümlaut än gravy":          "mlaut-n-gravy", // non-ASCII dibuang
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, mau %q", in, got, want)
		}
	}
	if got := Slugify(strings.Repeat("a", 300)); len(got) != 96 {
		t.Errorf("Slugify harus dibatasi 96 karakter, dapat %d", len(got))
	}
}
