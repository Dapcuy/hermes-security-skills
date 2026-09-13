package main

// Subcommand case brief & case list (ROADMAP §27 — memory diperkuat).
//
//	case brief --case <id>   ringkasan konteks satu case dalam satu output
//	case list                daftar semua case dari jobs/ + status
//
// Tiga sumber data read-only untuk brief:
//
//  1. jobs/<case>/          workspace engagement — status aktif/aborted
//                           (marker ABORTED, kill switch §10/§18);
//  2. approval store        record approval per case dengan state
//                           aktif/revoked/expired/habis + sisa budget (§9);
//  3. event index           evidence proxy yang membawa case_id — jumlah
//                           request, distribusi method, rentang waktu, dan
//                           evidence terakhir beserta sha256-nya (§25).
//
// Semua operasi read-only (tidak ada state yang diubah) dan menulis audit
// entry (§35). Fail-closed: approval store korup / evidence tamper = error,
// tidak pernah diringkas diam-diam.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/events"
	"hermes-security-skills/internal/jobs"
)

// caseApprovalView tampilan ringkas satu approval untuk output brief.
type caseApprovalView struct {
	ID        string
	State     string // aktif | revoked | expired | habis
	Remaining int    // sisa request budget (max - used, >= 0)
	Max       int
	Used      int
	Method    string
	Host      string
	Path      string
	Reason    string // alasan revoke (bila ada)
}

// caseBrief hasil pengumpulan konteks satu case.
type caseBrief struct {
	CaseID       string
	WorkspaceDir string // path jobs/<case> (relatif; kosong bila belum ada)
	Workspace    string // aktif | aborted | kosong
	Approvals    []caseApprovalView
	TotalReq     int
	PerMethod    map[string]int // method -> jumlah request
	FirstTS      string         // captured_at evidence pertama (kosong bila tidak ada)
	LastTS       string         // captured_at evidence terakhir
	LastRef      string         // evidence file terakhir
	LastSHA      string         // sha256 evidence terakhir
	EvidenceDir  string         // path evidence dir yang diindeks
}

// collectCaseBrief mengumpulkan konteks case dari jobs/, approval store, dan
// event index. now di-inject agar testable. Fail-closed:
//   - case id tidak valid (bukan slug jobs) = error (path traversal tolak);
//   - approval store korup = error;
//   - evidence dir ada tetapi gagal diindeks (tamper §25) = error.
//     Evidence dir BELUM ada = kondisi normal (case tanpa traffic) — bukan error.
func collectCaseBrief(jobsRoot, stateDir, evidenceDir, caseID string, now time.Time) (*caseBrief, error) {
	if !jobs.ValidID(caseID) {
		return nil, fmt.Errorf("case brief: case id %q tidak valid (huruf/angka/._- , maks 64)", caseID)
	}
	b := &caseBrief{
		CaseID:      caseID,
		PerMethod:   map[string]int{},
		EvidenceDir: filepath.ToSlash(filepath.Clean(evidenceDir)),
	}

	// 1) Workspace jobs/<case> (status aktif/aborted/kosong).
	wsDir := filepath.Join(filepath.Clean(jobsRoot), caseID)
	b.WorkspaceDir = filepath.ToSlash(wsDir)
	if fi, err := os.Stat(wsDir); err == nil && fi.IsDir() {
		if jobs.IsAborted(filepath.Clean(jobsRoot), caseID) {
			b.Workspace = "aborted"
		} else {
			b.Workspace = "aktif"
		}
	} else {
		b.Workspace = "kosong"
	}

	// 2) Approval store (§9): state per record + sisa budget.
	store := approval.OpenStore(filepath.Join(stateDir, "approvals.json"))
	recs, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("case brief: %w", err)
	}
	for _, r := range recs {
		if r.CaseID != caseID {
			continue
		}
		v := caseApprovalView{
			ID: r.ID, Max: r.MaxRequests, Used: r.Used,
			Method: r.Method, Host: r.Host, Path: r.Path, Reason: r.RevokeReason,
		}
		v.Remaining = r.MaxRequests - r.Used
		if v.Remaining < 0 {
			v.Remaining = 0
		}
		switch {
		case r.Revoked:
			v.State = "revoked"
		case !now.Before(r.ExpiresAt):
			v.State = "expired"
		case r.Used >= r.MaxRequests:
			v.State = "habis"
		default:
			v.State = "aktif"
		}
		b.Approvals = append(b.Approvals, v)
	}
	sort.Slice(b.Approvals, func(i, j int) bool { return b.Approvals[i].ID < b.Approvals[j].ID })

	// 3) Event index (§25): evidence yang membawa case_id ini.
	if fi, err := os.Stat(evidenceDir); err == nil && fi.IsDir() {
		st, err := events.LoadEvidenceDir(evidenceDir)
		if err != nil {
			// Tamper/korup tidak boleh diringkas diam-diam (fail-closed §25).
			return nil, fmt.Errorf("case brief: event index: %w", err)
		}
		entries := st.List(events.ListFilter{CaseID: caseID})
		b.TotalReq = len(entries)
		for _, e := range entries {
			b.PerMethod[e.Method]++
			if b.FirstTS == "" {
				b.FirstTS = e.TS
			}
			b.LastTS = e.TS
			b.LastRef = e.EvidenceRef
			b.LastSHA = e.SHA256
		}
	}
	return b, nil
}

// renderCaseBrief merender brief menjadi teks rapi. Case kosong tetap
// menghasilkan output jujur dengan catatan eksplisit per sumber data.
func renderCaseBrief(b *caseBrief) string {
	var w strings.Builder
	fmt.Fprintf(&w, "case brief: %s\n", b.CaseID)
	switch b.Workspace {
	case "aborted":
		fmt.Fprintf(&w, "  status case   : ABORTED (%s — task/eksekusi baru ditolak, §10)\n", b.WorkspaceDir)
	case "aktif":
		fmt.Fprintf(&w, "  status case   : aktif (%s)\n", b.WorkspaceDir)
	default:
		fmt.Fprintf(&w, "  status case   : belum ada workspace %s (case belum pernah dipakai task/abort)\n", b.WorkspaceDir)
	}

	if len(b.Approvals) == 0 {
		w.WriteString("  approval      : tidak ada record untuk case ini (store kosong / case lain)\n")
	} else {
		active := 0
		for _, a := range b.Approvals {
			if a.State == "aktif" {
				active++
			}
		}
		fmt.Fprintf(&w, "  approval      : %d record (%d aktif)\n", len(b.Approvals), active)
		for _, a := range b.Approvals {
			line := fmt.Sprintf("    - %s [%s] sisa=%d/%d %s %s%s",
				a.ID, a.State, a.Remaining, a.Max, a.Method, a.Host, a.Path)
			if a.Reason != "" {
				line += " (" + a.Reason + ")"
			}
			w.WriteString(line + "\n")
		}
	}

	if b.TotalReq == 0 {
		fmt.Fprintf(&w, "  request       : 0 (belum ada evidence dengan case_id %q di %s)\n", b.CaseID, b.EvidenceDir)
	} else {
		methods := make([]string, 0, len(b.PerMethod))
		for m := range b.PerMethod {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		parts := make([]string, 0, len(methods))
		for _, m := range methods {
			parts = append(parts, fmt.Sprintf("%s=%d", m, b.PerMethod[m]))
		}
		fmt.Fprintf(&w, "  request       : %d (per method: %s)\n", b.TotalReq, strings.Join(parts, ", "))
		fmt.Fprintf(&w, "  rentang waktu : %s .. %s\n", b.FirstTS, b.LastTS)
		fmt.Fprintf(&w, "  evidence      : %s (sha256 %s)\n", b.LastRef, b.LastSHA)
	}
	return w.String()
}

// caseBriefCmd menangani `case brief --case <id>`.
func caseBriefCmd(args []string) error {
	fs := newFlagSet("case brief")
	caseID := fs.String("case", "", "case id yang diringkas (wajib)")
	jobsDirFlag := fs.String("jobs-dir", defaultJobsDir, "root direktori jobs workspace (§18)")
	stateDirFlag := fs.String("state-dir", defaultJobsDir, "direktori approval store (approvals.json)")
	evidenceDirFlag := fs.String("evidence-dir", defaultEvidenceDir, "direktori evidence hermes-proxy (event index §25)")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("case brief: --case wajib diisi")
	}
	b, err := collectCaseBrief(*jobsDirFlag, *stateDirFlag, *evidenceDirFlag, *caseID, time.Now().UTC())
	if err != nil {
		_ = writeAudit(*auditFile, "case_brief", map[string]any{
			"case": *caseID, "result": "error", "error": err.Error(),
		})
		return err
	}
	fmt.Print(renderCaseBrief(b))
	return writeAudit(*auditFile, "case_brief", map[string]any{
		"case": b.CaseID, "workspace": b.Workspace,
		"approvals": len(b.Approvals), "requests": b.TotalReq, "result": "ok",
	})
}

// caseSummary satu baris `case list`.
type caseSummary struct {
	ID     string
	Status string // aktif | aborted
}

// collectCaseList mendaftar semua case dari jobs root (read-only).
// Direktori evidence dikecualikan; direktori bernama non-case-id tetap
// dilaporkan dengan status "id-tidak-valid" (tidak ada skip senyap).
func collectCaseList(jobsRoot, evidenceDir string) ([]caseSummary, error) {
	root := filepath.Clean(jobsRoot)
	dirs, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // jobs/ belum ada = belum ada case
		}
		return nil, fmt.Errorf("case list: baca %s: %w", root, err)
	}
	evAbs, err := filepath.Abs(evidenceDir)
	if err != nil {
		return nil, fmt.Errorf("case list: resolve evidence-dir: %w", err)
	}
	out := make([]caseSummary, 0, len(dirs))
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dirAbs, err := filepath.Abs(filepath.Join(root, d.Name()))
		if err != nil {
			return nil, fmt.Errorf("case list: resolve %s: %w", d.Name(), err)
		}
		if filepath.Clean(dirAbs) == filepath.Clean(evAbs) {
			continue // evidence store bukan case
		}
		if !jobs.ValidID(d.Name()) {
			out = append(out, caseSummary{ID: d.Name(), Status: "id-tidak-valid"})
			continue
		}
		status := "aktif"
		if jobs.IsAborted(root, d.Name()) {
			status = "aborted"
		}
		out = append(out, caseSummary{ID: d.Name(), Status: status})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// caseListCmd menangani `case list`.
func caseListCmd(args []string) error {
	fs := newFlagSet("case list")
	jobsDirFlag := fs.String("jobs-dir", defaultJobsDir, "root direktori jobs workspace (§18)")
	evidenceDirFlag := fs.String("evidence-dir", defaultEvidenceDir, "direktori evidence (dikecualikan dari daftar case)")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cases, err := collectCaseList(*jobsDirFlag, *evidenceDirFlag)
	if err != nil {
		_ = writeAudit(*auditFile, "case_list", map[string]any{
			"result": "error", "error": err.Error(),
		})
		return err
	}
	if len(cases) == 0 {
		fmt.Printf("case list: belum ada case di %s\n", filepath.ToSlash(filepath.Clean(*jobsDirFlag)))
	} else {
		fmt.Printf("case list (%d) dari %s:\n", len(cases), filepath.ToSlash(filepath.Clean(*jobsDirFlag)))
		for _, c := range cases {
			fmt.Printf("  %-32s %s\n", c.ID, c.Status)
		}
	}
	return writeAudit(*auditFile, "case_list", map[string]any{
		"count": len(cases), "result": "ok",
	})
}
