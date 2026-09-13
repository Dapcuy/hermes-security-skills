package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"hermes-security-skills/internal/memory"
)

// Subcommand knowledge & case (ROADMAP §27, §41 — Phase 10):
//
//	knowledge ingest <file> --category <c> --source <s> --confidence <f>
//	knowledge list   [--state s] [--category c]
//	knowledge search <query>
//	knowledge review <id> --state reviewed     (human-in-the-loop, §27)
//	knowledge stale                            (MarkStale, report)
//	case archive --case <id>                   (retention, §25)
//
// Implementasi case brief/list ada di casebrief.go (memory diperkuat).
//
// Semua operasi menulis audit entry (§35). Penyimpanan berada di
// knowledge/ (canonical|proposed|reviewed) dan memory/cases/<caseID>.
// Konten target HANYA bisa masuk lewat jalur programatik
// memory.Store.IngestFromTarget — tidak ada perintah CLI yang
// mengeksposnya (knowledge firewall §24).

const (
	defaultKnowledgeDir = "knowledge"
	defaultMemoryDir    = "memory"
)

// knowledgeFlags: flag bersama subcommand knowledge.
type knowledgeFlags struct {
	knowledgeDir *string
	memoryDir    *string
	auditFile    *string
}

func parseKnowledgeFlags(fs *flag.FlagSet) *knowledgeFlags {
	kf := &knowledgeFlags{
		knowledgeDir: fs.String("knowledge-dir", defaultKnowledgeDir, "root direktori knowledge base"),
		memoryDir:    fs.String("memory-dir", defaultMemoryDir, "root direktori memory (cases di bawahnya)"),
		auditFile:    auditFlag(fs),
	}
	return kf
}

func (kf *knowledgeFlags) store() *memory.Store {
	return memory.NewStore(*kf.knowledgeDir, *kf.memoryDir)
}

// parseMixedArgs memisahkan argumen posisional dari flag lalu mem-parse
// flag-nya. Dipakai karena flag stdlib Go berhenti pada argumen non-flag
// pertama, sementara konvensi CLI di sini menaruh posisional di depan
// (mis. `knowledge ingest <file> --category c`).
// Flag yang mengambil nilai terpisah (--flag value) ditentukan lewat
// definisi FlagSet itu sendiri, bukan tebakan.
func parseMixedArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" || a == "--" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // bentuk --flag=value: nilai sudah menyatu
		}
		if f := fs.Lookup(name); f != nil && takesValue(f) && i+1 < len(args) {
			i++
			flags = append(flags, args[i]) // nilai flag ikut ke parser
		}
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return positional, nil
}

// boolFlagValue mendeteksi flag boolean (tidak mengambil nilai terpisah).
type boolFlagValue interface{ IsBoolFlag() bool }

func takesValue(f *flag.Flag) bool {
	bv, ok := f.Value.(boolFlagValue)
	return !ok || !bv.IsBoolFlag()
}

func cmdKnowledge(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("knowledge: butuh subcommand (ingest|list|search|review|stale)")
	}
	switch args[0] {
	case "ingest":
		return knowledgeIngest(args[1:])
	case "list":
		return knowledgeList(args[1:])
	case "search":
		return knowledgeSearch(args[1:])
	case "review":
		return knowledgeReview(args[1:])
	case "stale":
		return knowledgeStale(args[1:])
	default:
		return fmt.Errorf("knowledge: subcommand tidak dikenal %q (ingest|list|search|review|stale)", args[0])
	}
}

// ------------------------------------------------------------- knowledge ingest

func knowledgeIngest(args []string) error {
	fs := newFlagSet("knowledge ingest")
	kf := parseKnowledgeFlags(fs)
	category := fs.String("category", "", "kategori entry, mis. xss-analysis (wajib)")
	source := fs.String("source", "", "asal entry, mis. manual-research (wajib)")
	confidence := fs.Float64("confidence", -1, "confidence 0..1 (opsional; default dari frontmatter — wajib salah satu)")
	expires := fs.String("expires", "", "opsional: kedaluwarsa RFC3339 (mis. 2026-12-31T00:00:00Z)")
	positional, err := parseMixedArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("knowledge ingest: butuh tepat satu path file entry")
	}
	if strings.TrimSpace(*category) == "" || strings.TrimSpace(*source) == "" {
		return fmt.Errorf("knowledge ingest: --category dan --source wajib diisi")
	}
	if *confidence > 1 {
		return fmt.Errorf("knowledge ingest: --confidence harus di rentang 0..1")
	}
	meta := memory.IngestMeta{Category: *category, Source: *source}
	if *confidence >= 0 {
		meta.Confidence = confidence
	}
	if strings.TrimSpace(*expires) != "" {
		t, err := time.Parse(time.RFC3339, *expires)
		if err != nil {
			return fmt.Errorf("knowledge ingest: --expires bukan RFC3339: %v", err)
		}
		meta.ExpiresAt = &t
	}
	e, err := kf.store().Ingest(positional[0], meta)
	if err != nil {
		// Kegagalan (termasuk penolakan firewall) tetap ter-audit.
		_ = writeAudit(*kf.auditFile, "knowledge_ingest", map[string]any{
			"file": filepathToSlash(positional[0]), "result": "error", "error": err.Error(),
		})
		return err
	}
	fmt.Printf("knowledge ingest: OK\n")
	fmt.Printf("  id          : %s\n", e.ID)
	fmt.Printf("  title       : %s\n", e.Title)
	fmt.Printf("  state       : %s (knowledge/proposed — menunggu review, §27)\n", e.State)
	fmt.Printf("  confidence  : %.2f\n", e.Confidence)
	return writeAudit(*kf.auditFile, "knowledge_ingest", map[string]any{
		"id": e.ID, "category": e.Category, "source": e.Source,
		"state": string(e.State), "result": "ok",
	})
}

// -------------------------------------------------------------- knowledge list

func knowledgeList(args []string) error {
	fs := newFlagSet("knowledge list")
	kf := parseKnowledgeFlags(fs)
	state := fs.String("state", "", "filter state (captured|normalized|proposed|reviewed|trusted|stale|archived)")
	category := fs.String("category", "", "filter kategori")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f := memory.Filter{}
	if strings.TrimSpace(*state) != "" {
		if !memory.ValidState(memory.State(*state)) {
			return fmt.Errorf("knowledge list: state %q tidak dikenal", *state)
		}
		f.State = memory.State(*state)
	}
	f.Category = strings.TrimSpace(*category)
	entries, err := kf.store().List(f)
	if err != nil {
		return err
	}
	if *asJSON {
		out, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	} else {
		fmt.Printf("Entries (%d):\n", len(entries))
		for _, e := range entries {
			fmt.Printf("  %-28s %-10s %-20s conf=%.2f trust=%-9s %s\n",
				e.ID, e.State, e.Category, e.Confidence, e.Provenance.Trust, truncateRunes(e.Title, 48))
		}
	}
	return writeAudit(*kf.auditFile, "knowledge_list", map[string]any{
		"state": *state, "category": *category, "count": len(entries),
	})
}

// ------------------------------------------------------------ knowledge search

func knowledgeSearch(args []string) error {
	fs := newFlagSet("knowledge search")
	kf := parseKnowledgeFlags(fs)
	positional, err := parseMixedArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("knowledge search: butuh tepat satu query")
	}
	query := positional[0]
	results, err := kf.store().Search(query)
	if err != nil {
		return err
	}
	fmt.Printf("Search %q (%d hasil):\n", query, len(results))
	for _, s := range results {
		fmt.Printf("  skor=%-3d %-28s %-10s %s\n",
			s.Score, s.Entry.ID, s.Entry.State, truncateRunes(s.Entry.Title, 48))
	}
	return writeAudit(*kf.auditFile, "knowledge_search", map[string]any{
		"query": query, "count": len(results),
	})
}

// ----------------------------------------------------------- knowledge review

func knowledgeReview(args []string) error {
	fs := newFlagSet("knowledge review")
	kf := parseKnowledgeFlags(fs)
	target := fs.String("state", "", "state tujuan setelah review (mis. reviewed; wajib)")
	positional, err := parseMixedArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("knowledge review: butuh tepat satu id entry")
	}
	if strings.TrimSpace(*target) == "" {
		return fmt.Errorf("knowledge review: --state wajib diisi (human-in-the-loop, §27)")
	}
	newState := memory.State(*target)
	if !memory.ValidState(newState) {
		return fmt.Errorf("knowledge review: state %q tidak dikenal", *target)
	}
	before, err := kf.store().Get(positional[0])
	if err != nil {
		return fmt.Errorf("knowledge review: %v", err)
	}
	e, err := kf.store().SetState(positional[0], newState)
	if err != nil {
		_ = writeAudit(*kf.auditFile, "knowledge_review", map[string]any{
			"id": fs.Arg(0), "from": string(before.State), "to": string(newState),
			"result": "error", "error": err.Error(),
		})
		return err
	}
	fmt.Printf("knowledge review: %s %s -> %s\n", e.ID, before.State, e.State)
	fmt.Printf("  last_reviewed: %s\n", e.LastReviewed.Format(time.RFC3339))
	return writeAudit(*kf.auditFile, "knowledge_review", map[string]any{
		"id": e.ID, "from": string(before.State), "to": string(e.State),
		"trust": string(e.Provenance.Trust), "result": "ok",
	})
}

// ------------------------------------------------------------ knowledge stale

func knowledgeStale(args []string) error {
	fs := newFlagSet("knowledge stale")
	kf := parseKnowledgeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	marked, err := kf.store().MarkStale(time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Printf("knowledge stale: %d entry ditandai stale (ambang %d hari, §41)\n",
		len(marked), int(memory.MarkStaleHorizon().Hours()/24))
	for _, id := range marked {
		fmt.Printf("  - %s\n", id)
	}
	return writeAudit(*kf.auditFile, "knowledge_stale", map[string]any{
		"marked": marked, "count": len(marked),
	})
}

// ------------------------------------------------------------------ case archive

func cmdCase(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("case: butuh subcommand (archive|brief|list)")
	}
	switch args[0] {
	case "archive":
		return caseArchive(args[1:])
	case "brief":
		return caseBriefCmd(args[1:])
	case "list":
		return caseListCmd(args[1:])
	default:
		return fmt.Errorf("case: subcommand tidak dikenal %q (archive|brief|list)", args[0])
	}
}

// caseArchive memproses retention policy satu case (§25): entry yang
// expires_at-nya lewat diarsipkan; bila semua sudah archived, direktori
// case dipindah ke memory/cases/<caseID>.archived.
func caseArchive(args []string) error {
	fs := newFlagSet("case archive")
	caseID := fs.String("case", "", "case id yang diarsipkan (wajib)")
	memoryDir := fs.String("memory-dir", defaultMemoryDir, "root direktori memory")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("case archive: --case wajib diisi")
	}
	res, err := memory.NewStore(defaultKnowledgeDir, *memoryDir).Retention(*caseID, time.Now().UTC())
	if err != nil {
		_ = writeAudit(*auditFile, "case_archive", map[string]any{
			"case": *caseID, "result": "error", "error": err.Error(),
		})
		return err
	}
	fmt.Printf("case archive: %s\n", res.CaseID)
	fmt.Printf("  entry diarsipkan : %d %v\n", len(res.ArchivedEntries), res.ArchivedEntries)
	fmt.Printf("  entry tersisa    : %d %v\n", len(res.Remaining), res.Remaining)
	if res.CaseArchived {
		fmt.Printf("  direktori case   : %s (semua entry expired, §25)\n", filepathToSlash(res.ArchivedPath))
	} else {
		fmt.Println("  direktori case   : masih aktif (ada entry yang belum expired)")
	}
	return writeAudit(*auditFile, "case_archive", map[string]any{
		"case": res.CaseID, "archived_entries": res.ArchivedEntries,
		"remaining": res.Remaining, "case_archived": res.CaseArchived,
		"archived_path": filepathToSlash(res.ArchivedPath), "result": "ok",
	})
}

// truncateRunes memotong string pada batas rune untuk output tabel.
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// filepathToSlash: path dengan pemisah slash untuk output/audit yang
// konsisten lintas platform.
func filepathToSlash(p string) string {
	return filepath.ToSlash(p)
}
