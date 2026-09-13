package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/jobs"
	"hermes-security-skills/internal/proxycore"
)

// caseTestEnv menyiapkan fixture lengkap untuk case brief/list:
//
//	jobsRoot/
//	  case-a/                    workspace aktif
//	  case-b/ABORTED             workspace aborted
//	  evidence/evidence-*.json   evidence proxy (2 untuk case-a, 1 untuk case-b)
//	stateDir/approvals.json      record approval: case-a (aktif/revoked/expired), case-c (aktif)
type caseTestEnv struct {
	jobsRoot    string
	stateDir    string
	evidenceDir string
	now         time.Time
}

// writeApprovalStore menulis approvals.json secara langsung (bentuk file
// identik dengan keluaran approval.Store) agar bisa mencampur record revoked
// tanpa menyentuh case lain lewat RevokeCase (yang bekerja per case).
func writeApprovalStore(t *testing.T, path string, recs []approval.Record) {
	t.Helper()
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newCaseTestEnv(t *testing.T) *caseTestEnv {
	t.Helper()
	root := t.TempDir()
	env := &caseTestEnv{
		jobsRoot:    filepath.Join(root, "jobs"),
		stateDir:    filepath.Join(root, "jobs"),
		evidenceDir: filepath.Join(root, "jobs", "evidence"),
		now:         time.Now().UTC().Add(time.Hour),
	}
	for _, d := range []string{"case-a", "case-b", "evidence"} {
		if err := os.MkdirAll(filepath.Join(env.jobsRoot, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// case-b di-abort (kill switch §10).
	if _, err := jobs.MarkAborted(env.jobsRoot, "case-b"); err != nil {
		t.Fatal(err)
	}

	// Evidence via proxycore.EvidenceStore — format identik hermes-proxy.
	es, err := proxycore.NewEvidenceStore(env.evidenceDir)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(method, url, caseID string) proxycore.EvidenceRecord {
		return proxycore.EvidenceRecord{
			CaseID: caseID,
			Request: proxycore.EvidenceRequest{
				Method: method, URL: url, Headers: proxycore.RedactHeaders(http.Header{}),
				BodyEncoding: "base64",
			},
			Response: proxycore.EvidenceResponse{
				Status: 200, Headers: proxycore.RedactHeaders(http.Header{}),
				BodyEncoding: "base64",
			},
		}
	}
	for _, rec := range []proxycore.EvidenceRecord{
		mk("GET", "http://localhost:8901/a1", "case-a"),
		mk("POST", "http://localhost:8901/a2", "case-a"),
		mk("GET", "http://localhost:8901/b1", "case-b"),
	} {
		if _, _, err := es.Write(rec); err != nil {
			t.Fatal(err)
		}
	}

	// Approval store: 3 state berbeda untuk case-a + 1 record case lain.
	exp := env.now.Add(time.Hour).UTC()
	past := env.now.Add(-time.Hour).UTC()
	writeApprovalStore(t, filepath.Join(env.stateDir, "approvals.json"), []approval.Record{
		{
			ID: "app-aktif", CaseID: "case-a", Capability: "request_replay",
			Host: "localhost", Method: "GET", Path: approval.PathAny,
			MaxRequests: 5, Used: 2, ExpiresAt: exp, Risk: "medium",
			CreatedAt: env.now.Add(-2 * time.Hour).UTC(),
		},
		{
			ID: "app-revoked", CaseID: "case-a", Capability: "request_replay",
			Host: "localhost", Method: "POST", Path: "/api",
			MaxRequests: 3, ExpiresAt: exp, Risk: "high",
			CreatedAt: env.now.Add(-2 * time.Hour).UTC(),
			Revoked:   true, RevokedAt: env.now.Add(-time.Hour).UTC(),
			RevokeReason: approval.ReasonRevokedByAbort,
		},
		{
			ID: "app-expired", CaseID: "case-a", Capability: "request_replay",
			Host: "localhost", Method: "GET", Path: "/old",
			MaxRequests: 2, ExpiresAt: past, Risk: "low",
			CreatedAt: env.now.Add(-3 * time.Hour).UTC(),
		},
		{
			ID: "app-lain", CaseID: "case-c", Capability: "request_replay",
			Host: "localhost", Method: "GET", Path: approval.PathAny,
			MaxRequests: 1, ExpiresAt: exp, Risk: "low",
			CreatedAt: env.now.Add(-2 * time.Hour).UTC(),
		},
	})
	return env
}

// TestCollectCaseBriefFull: case-a — workspace aktif, 3 approval dengan state
// berbeda, evidence terindeks dengan statistik method dan sha256 terakhir.
func TestCollectCaseBriefFull(t *testing.T) {
	env := newCaseTestEnv(t)
	b, err := collectCaseBrief(env.jobsRoot, env.stateDir, env.evidenceDir, "case-a", env.now)
	if err != nil {
		t.Fatalf("collectCaseBrief: %v", err)
	}
	if b.Workspace != "aktif" {
		t.Errorf("workspace = %q, mau aktif", b.Workspace)
	}
	if len(b.Approvals) != 3 {
		t.Fatalf("approvals = %d, mau 3 (%+v)", len(b.Approvals), b.Approvals)
	}
	// Urutan deterministik by id.
	wantStates := map[string]string{
		"app-aktif": "aktif", "app-expired": "expired", "app-revoked": "revoked",
	}
	for _, a := range b.Approvals {
		if wantStates[a.ID] != a.State {
			t.Errorf("approval %s state = %q, mau %q", a.ID, a.State, wantStates[a.ID])
		}
	}
	if b.Approvals[0].ID != "app-aktif" {
		t.Errorf("urutan pertama = %q, mau app-aktif", b.Approvals[0].ID)
	}
	if b.Approvals[0].Remaining != 3 || b.Approvals[0].Max != 5 || b.Approvals[0].Used != 2 {
		t.Errorf("budget salah: %+v", b.Approvals[0])
	}
	for _, a := range b.Approvals {
		if a.ID == "app-revoked" && a.Reason != approval.ReasonRevokedByAbort {
			t.Errorf("alasan revoke harus terbawa: %+v", a)
		}
	}
	if b.TotalReq != 2 {
		t.Errorf("total request = %d, mau 2", b.TotalReq)
	}
	if b.PerMethod["GET"] != 1 || b.PerMethod["POST"] != 1 {
		t.Errorf("per method salah: %v", b.PerMethod)
	}
	if b.FirstTS == "" || b.LastTS == "" {
		t.Errorf("rentang waktu kosong: %q..%q", b.FirstTS, b.LastTS)
	}
	if b.LastRef != "evidence-000002.json" {
		t.Errorf("last ref = %q, mau evidence-000002.json", b.LastRef)
	}
	if len(b.LastSHA) != 64 {
		t.Errorf("last sha256 = %q, mau hex 64 char", b.LastSHA)
	}
}

// TestCollectCaseBriefAborted: case-b — workspace aborted, satu evidence
// GET, tanpa approval untuk case ini.
func TestCollectCaseBriefAborted(t *testing.T) {
	env := newCaseTestEnv(t)
	b, err := collectCaseBrief(env.jobsRoot, env.stateDir, env.evidenceDir, "case-b", env.now)
	if err != nil {
		t.Fatalf("collectCaseBrief: %v", err)
	}
	if b.Workspace != "aborted" {
		t.Errorf("workspace = %q, mau aborted", b.Workspace)
	}
	if len(b.Approvals) != 0 {
		t.Errorf("approvals = %d, mau 0", len(b.Approvals))
	}
	if b.TotalReq != 1 || b.PerMethod["GET"] != 1 {
		t.Errorf("statistik request salah: total=%d permethod=%v", b.TotalReq, b.PerMethod)
	}
}

// TestCollectCaseBriefEmpty: case yang belum pernah ada — status kosong dan
// semua sumber data kosong (bukan error; output jujur).
func TestCollectCaseBriefEmpty(t *testing.T) {
	env := newCaseTestEnv(t)
	b, err := collectCaseBrief(env.jobsRoot, env.stateDir, env.evidenceDir, "case-kosong", env.now)
	if err != nil {
		t.Fatalf("collectCaseBrief: %v", err)
	}
	if b.Workspace != "kosong" || len(b.Approvals) != 0 || b.TotalReq != 0 {
		t.Errorf("brief kosong salah: %+v", b)
	}
	out := renderCaseBrief(b)
	if !strings.Contains(out, "belum ada workspace") || !strings.Contains(out, "tidak ada record") {
		t.Errorf("output harus berisi catatan kosong yang jujur:\n%s", out)
	}
}

// TestCollectCaseBriefInvalidID: path traversal / id invalid ditolak
// fail-closed. Catatan: brief memakai jobs.ValidID (konvensi jobs/<case>,
// boleh huruf besar) — lebih longgar dari slug proxy [a-z0-9-].
func TestCollectCaseBriefInvalidID(t *testing.T) {
	env := newCaseTestEnv(t)
	for _, id := range []string{"../evil", "", "a b", "."} {
		if _, err := collectCaseBrief(env.jobsRoot, env.stateDir, env.evidenceDir, id, env.now); err == nil {
			t.Errorf("case id %q harus ditolak", id)
		}
	}
}

// TestRenderCaseBrief: output teks memuat bagian wajib.
func TestRenderCaseBrief(t *testing.T) {
	env := newCaseTestEnv(t)
	b, err := collectCaseBrief(env.jobsRoot, env.stateDir, env.evidenceDir, "case-a", env.now)
	if err != nil {
		t.Fatal(err)
	}
	out := renderCaseBrief(b)
	for _, want := range []string{
		"case brief: case-a", "status case   : aktif",
		"app-aktif [aktif] sisa=3/5", "app-revoked [revoked]", "app-expired [expired]",
		"request       : 2 (per method: GET=1, POST=1)",
		"rentang waktu", "evidence      : evidence-000002.json (sha256 ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output kurang %q:\n%s", want, out)
		}
	}
}

// TestCollectCaseList: daftar case + status, evidence dir dikecualikan.
func TestCollectCaseList(t *testing.T) {
	env := newCaseTestEnv(t)
	cases, err := collectCaseList(env.jobsRoot, env.evidenceDir)
	if err != nil {
		t.Fatalf("collectCaseList: %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("cases = %d, mau 2 (%+v)", len(cases), cases)
	}
	if cases[0].ID != "case-a" || cases[0].Status != "aktif" {
		t.Errorf("case[0] salah: %+v", cases[0])
	}
	if cases[1].ID != "case-b" || cases[1].Status != "aborted" {
		t.Errorf("case[1] salah: %+v", cases[1])
	}
}

// TestCollectCaseListEmptyRoot: jobs/ belum ada = daftar kosong, bukan error.
func TestCollectCaseListEmptyRoot(t *testing.T) {
	cases, err := collectCaseList(filepath.Join(t.TempDir(), "tidak-ada"), "")
	if err != nil {
		t.Fatalf("jobs root hilang harus nil error: %v", err)
	}
	if len(cases) != 0 {
		t.Errorf("mau 0 case, dapat %d", len(cases))
	}
}
