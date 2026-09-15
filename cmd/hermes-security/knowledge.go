package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hermes-security-skills/internal/jobs"
	"hermes-security-skills/internal/knowledge"
	"hermes-security-skills/internal/recovery"
)

// Subcommand knowledge & case (ROADMAP v3.0 §20, §23, §24, §61 — Phase 11):
//
//	knowledge ingest <file> --category <c> --source <s> --confidence <f>
//	knowledge list   [--state s] [--category c]
//	knowledge search <query>
//	knowledge review <id> --state reviewed     (human-in-the-loop, §23)
//	knowledge stale                            (MarkStale, report)
//	case clean <id> [--force] [--jobs-dir dir] (jobs cleanup — case
//	                                           retention §25, bukan memory)
//
// Sejak ROADMAP v3.0 memory DIHAPUS sebagai komponen (§24 Why Skill >
// Memory): state kasus hidup di evidence + jobs + approval + events.
// Knowledge base adalah curated reference — BUKAN memori agent.
//
// Knowledge firewall (§20, §23): konten target-controlled tidak boleh masuk
// knowledge base — ingest menolaknya fail-closed (konten target hidup di
// evidence). Tidak ada perintah CLI maupun jalur programatik yang
// mengekspos konten target ke knowledge base.
//
// Implementasi case brief/list ada di casebrief.go (berbasis jobs +
// approval + events).

const defaultKnowledgeDir = "knowledge"

// knowledgeFlags: flag bersama subcommand knowledge.
type knowledgeFlags struct {
	knowledgeDir *string
	auditFile    *string
}

func parseKnowledgeFlags(fs *flag.FlagSet) *knowledgeFlags {
	return &knowledgeFlags{
		knowledgeDir: fs.String("knowledge-dir", defaultKnowledgeDir, "root direktori knowledge base"),
		auditFile:    auditFlag(fs),
	}
}

func (kf *knowledgeFlags) store() *knowledge.Store {
	return knowledge.NewStore(*kf.knowledgeDir)
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
	meta := knowledge.IngestMeta{Category: *category, Source: *source}
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
	fmt.Printf("  state       : %s (knowledge/research — menunggu review, §23)\n", e.State)
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
	f := knowledge.Filter{}
	if strings.TrimSpace(*state) != "" {
		if !knowledge.ValidState(knowledge.State(*state)) {
			return fmt.Errorf("knowledge list: state %q tidak dikenal", *state)
		}
		f.State = knowledge.State(*state)
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
		return fmt.Errorf("knowledge review: --state wajib diisi (human-in-the-loop, §23)")
	}
	newState := knowledge.State(*target)
	if !knowledge.ValidState(newState) {
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
	fmt.Printf("knowledge stale: %d entry ditandai stale (ambang %d hari, §61)\n",
		len(marked), int(knowledge.MarkStaleHorizon().Hours()/24))
	for _, id := range marked {
		fmt.Printf("  - %s\n", id)
	}
	return writeAudit(*kf.auditFile, "knowledge_stale", map[string]any{
		"marked": marked, "count": len(marked),
	})
}

// ------------------------------------------------------------------ case clean

func cmdCase(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("case: butuh subcommand (clean|brief|list)")
	}
	switch args[0] {
	case "clean":
		return caseClean(args[1:])
	case "brief":
		return caseBriefCmd(args[1:])
	case "list":
		return caseListCmd(args[1:])
	default:
		return fmt.Errorf("case: subcommand tidak dikenal %q (clean|brief|list)", args[0])
	}
}

// caseClean menghapus workspace jobs/<caseID> (case retention §25 — sejak
// v3.0 retention kasus adalah jobs cleanup, BUKAN memory): state kasus
// hidup di jobs/, dan pembersihannya berarti menghapus workspace tersebut.
//
// Fail-closed secara default: TANPA --force command hanya MENAMPILKAN isi
// yang akan dihapus lalu error (dry-run) — tidak ada penghapusan diam-diam.
// Dengan --force, direktori jobs/<caseID> dihapus hanya jika memenuhi
// minimum age dan seluruh top-level entry masuk allowlist.
//
// Yang TIDAK disentuh (jejak audit tetap utuh):
//   - audit log (append-only);
//   - approval store (approval expired/revoked oleh policy-nya sendiri);
//   - event index / evidence yang berada di luar jobs/<caseID>.
func caseClean(args []string) error {
	fs := newFlagSet("case clean")
	jobsDir := fs.String("jobs-dir", defaultJobsDir, "root direktori jobs")
	force := fs.Bool("force", false, "wajib untuk benar-benar menghapus (tanpa ini = dry-run)")
	minAge := fs.Duration("min-age", 24*time.Hour, "umur minimum case sebelum cleanup (mis. 24h; 0s untuk override eksplisit)")
	auditFile := auditFlag(fs)
	positional, err := parseMixedArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("case clean: butuh tepat satu case id")
	}
	caseID := positional[0]
	if !jobs.ValidID(caseID) {
		return fmt.Errorf("case clean: case id %q tidak valid (huruf/angka/._- , maks 64)", caseID)
	}
	caseDir := filepath.Join(*jobsDir, caseID)
	info, err := os.Stat(caseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("case clean: case %q tidak ditemukan (tidak ada %s)", caseID, filepathToSlash(caseDir))
		}
		return fmt.Errorf("case clean: stat %s: %w", caseDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("case clean: %s bukan direktori case", filepathToSlash(caseDir))
	}
	// Validasi retention dilakukan sebelum dry-run maupun delete: case muda,
	// symlink, dan entry asing harus selalu ditolak fail-closed.
	entries, err := os.ReadDir(caseDir)
	if err != nil {
		return fmt.Errorf("case clean: scan entries %s: %w", caseDir, err)
	}
	aborted := false
	if markerInfo, markerErr := os.Stat(filepath.Join(caseDir, jobs.AbortedFile)); markerErr == nil {
		aborted = !markerInfo.IsDir()
	}
	allowed := []string{jobs.AbortedFile}
	for _, entry := range entries {
		if entry.Name() == jobs.AbortedFile {
			continue
		}
		if !jobs.ValidID(entry.Name()) || !validRetentionWorkspace(filepath.Join(caseDir, entry.Name()), aborted) {
			return fmt.Errorf("case clean: entry %q tidak diizinkan oleh retention policy", entry.Name())
		}
		allowed = append(allowed, entry.Name())
	}
	files, size, err := recovery.ValidateCase(caseDir, recovery.RetentionPolicy{
		MinAge: *minAge, AllowedNames: allowed,
	}, time.Now().UTC())
	if err != nil {
		_ = writeAudit(*auditFile, "case_clean", map[string]any{
			"case": caseID, "jobs_dir": filepathToSlash(*jobsDir),
			"forced": *force, "result": "rejected", "error": err.Error(),
		})
		return fmt.Errorf("case clean: retention policy: %w", err)
	}
	if !*force {
		// Dry-run: tampilkan apa yang akan dihapus, lalu gagal (fail-closed —
		// penghapusan butuh konfirmasi eksplisit --force).
		fmt.Printf("case clean (dry-run): %s\n", filepathToSlash(caseDir))
		fmt.Printf("  file           : %d (%d bytes)\n", files, size)
		fmt.Println("  tidak ada yang dihapus — tambahkan --force untuk menghapus")
		_ = writeAudit(*auditFile, "case_clean", map[string]any{
			"case": caseID, "jobs_dir": filepathToSlash(*jobsDir),
			"files": files, "bytes": size, "forced": false, "result": "dry-run",
		})
		return fmt.Errorf("case clean: penghapusan butuh konfirmasi --force")
	}
	if err := recovery.CleanupCase(caseDir, recovery.RetentionPolicy{
		MinAge: *minAge, AllowedNames: allowed,
	}, time.Now().UTC()); err != nil {
		_ = writeAudit(*auditFile, "case_clean", map[string]any{
			"case": caseID, "jobs_dir": filepathToSlash(*jobsDir),
			"result": "error", "error": err.Error(),
		})
		return fmt.Errorf("case clean: retention cleanup %s: %w", filepathToSlash(caseDir), err)
	}
	if err := os.Remove(caseDir); err != nil {
		_ = writeAudit(*auditFile, "case_clean", map[string]any{
			"case": caseID, "jobs_dir": filepathToSlash(*jobsDir),
			"result": "error", "error": err.Error(),
		})
		return fmt.Errorf("case clean: remove empty case directory %s: %w", filepathToSlash(caseDir), err)
	}
	fmt.Printf("case clean: %s dihapus\n", filepathToSlash(caseDir))
	fmt.Printf("  file dihapus   : %d (%d bytes)\n", files, size)
	fmt.Println("  audit/approval : tidak disentuh (jejak audit tetap utuh)")
	return writeAudit(*auditFile, "case_clean", map[string]any{
		"case": caseID, "jobs_dir": filepathToSlash(*jobsDir),
		"files": files, "bytes": size, "forced": true, "result": "ok",
	})
}

func validRetentionWorkspace(dir string, aborted bool) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	for _, name := range []string{"input", "output", "artifacts", "logs"} {
		child, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !child.IsDir() || child.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	if aborted {
		return true
	}
	result, err := os.Lstat(filepath.Join(dir, "output", jobs.ResultFile))
	return err == nil && result.Mode().IsRegular() && result.Mode()&os.ModeSymlink == 0
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
