package approval

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func rec(caseID, method string, expires time.Time) Record {
	return Record{
		CaseID:      caseID,
		Capability:  "request_replay",
		Host:        "api.example.com",
		Method:      method,
		Path:        "/api/orders/123",
		MaxRequests: 2,
		ExpiresAt:   expires,
		Risk:        "medium",
	}
}

func TestStoreSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	st := OpenStore(path)
	exp := time.Now().Add(time.Hour).UTC()
	if err := st.Save(rec("case-001", "GET", exp)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Store baru (proses lain) harus membaca state yang sama.
	st2 := OpenStore(path)
	got, err := st2.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("mau 1 record, dapat %d", len(got))
	}
	if got[0].CaseID != "case-001" || got[0].Capability != "request_replay" ||
		got[0].Method != "GET" || got[0].MaxRequests != 2 {
		t.Errorf("record tidak sesuai: %+v", got[0])
	}
	if got[0].ID == "" {
		t.Error("ID harus digenerate otomatis saat kosong")
	}
}

func TestStoreSaveFailClosed(t *testing.T) {
	st := OpenStore(filepath.Join(t.TempDir(), "approvals.json"))
	exp := time.Now().Add(time.Hour)
	if err := st.Save(Record{Capability: "c", Host: "h", Method: "GET", Path: "/", MaxRequests: 1, ExpiresAt: exp, Risk: "low"}); err == nil {
		t.Error("case_id kosong harus error")
	}
	bad := rec("c", "GET", exp)
	bad.Path = ""
	if err := st.Save(bad); err == nil {
		t.Error("path kosong harus error")
	}
	bad = rec("c", "GET", exp)
	bad.MaxRequests = 0
	if err := st.Save(bad); err == nil {
		t.Error("max_requests 0 harus error")
	}
	bad = rec("c", "GET", time.Time{})
	if err := st.Save(bad); err == nil {
		t.Error("expires_at zero harus error")
	}
	// Duplicate ID ditolak.
	r := rec("c", "GET", exp)
	r.ID = "dup"
	if err := st.Save(r); err != nil {
		t.Fatalf("Save dup pertama: %v", err)
	}
	if err := st.Save(r); err == nil {
		t.Error("duplicate id harus error")
	}
}

func TestStoreRevokeCase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	st := OpenStore(path)
	exp := time.Now().Add(time.Hour).UTC()
	if err := st.Save(rec("case-001", "GET", exp)); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(rec("case-001", "POST", exp)); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(rec("case-002", "GET", exp)); err != nil {
		t.Fatal(err)
	}
	n, err := st.RevokeCase("case-001", ReasonRevokedByAbort)
	if err != nil {
		t.Fatalf("RevokeCase: %v", err)
	}
	if n != 2 {
		t.Fatalf("mau 2 record dicabut, dapat %d", n)
	}
	// Idempotent.
	if n, _ := st.RevokeCase("case-001", ReasonRevokedByAbort); n != 0 {
		t.Errorf("revoke ulang harus 0, dapat %d", n)
	}
	// State tersimpan: aktif case-001 kosong, case-002 tetap ada.
	st2 := OpenStore(path)
	act1, err := st2.Active("case-001")
	if err != nil {
		t.Fatal(err)
	}
	if len(act1) != 0 {
		t.Errorf("case-001 harus kosong setelah revoke, dapat %d", len(act1))
	}
	act2, err := st2.Active("case-002")
	if err != nil {
		t.Fatal(err)
	}
	if len(act2) != 1 {
		t.Errorf("case-002 harus tetap aktif, dapat %d", len(act2))
	}
	got, _ := st2.Load()
	for _, r := range got {
		if r.CaseID == "case-001" {
			if !r.Revoked || r.RevokeReason != ReasonRevokedByAbort || r.RevokedAt.IsZero() {
				t.Errorf("record revoke tidak lengkap: %+v", r)
			}
		}
	}
}

func TestStoreActiveFilterExpiredAndBudget(t *testing.T) {
	st := OpenStore(filepath.Join(t.TempDir(), "approvals.json"))
	now := time.Now()
	if err := st.Save(rec("c", "GET", now.Add(-time.Minute))); err != nil { // expired
		t.Fatal(err)
	}
	if err := st.Save(rec("c", "POST", now.Add(time.Hour))); err != nil { // aktif
		t.Fatal(err)
	}
	act, err := st.Active("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(act) != 1 || act[0].Method != "POST" {
		t.Fatalf("expired harus disaring; dapat %+v", act)
	}
}

func TestStoreFindActiveAndConsume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	st := OpenStore(path)
	exp := time.Now().Add(time.Hour).UTC()
	r := rec("case-001", "GET", exp)
	r.Path = PathAny
	if err := st.Save(r); err != nil {
		t.Fatal(err)
	}
	// Match wildcard path, method dinormalisasi lowercase dari caller.
	got, err := st.FindActive("request_replay", "case-001", "api.example.com", "get", "/whatever")
	if err != nil {
		t.Fatalf("FindActive: %v", err)
	}
	if got == nil {
		t.Fatal("harus ketemu (path wildcard)")
	}
	// Case berbeda TIDAK boleh memakai approval case lain (§9).
	if g, _ := st.FindActive("request_replay", "case-lain", "api.example.com", "GET", "/whatever"); g != nil {
		t.Error("approval case lain tidak boleh match")
	}
	// Consume sampai habis.
	for i := 0; i < r.MaxRequests; i++ {
		if err := st.Consume(got.ID); err != nil {
			t.Fatalf("Consume %d: %v", i+1, err)
		}
	}
	if err := st.Consume(got.ID); !errors.Is(err, ErrExhausted) {
		t.Errorf("budget habis = %v, mau ErrExhausted", err)
	}
	// Setelah habis, FindActive tidak lagi mengembalikan record.
	got2, err := st.FindActive("request_replay", "case-001", "api.example.com", "GET", "/whatever")
	if err != nil {
		t.Fatal(err)
	}
	if got2 != nil {
		t.Error("record habis tidak boleh dianggap aktif")
	}
	// Path exact tidak match wildcard sebaliknya.
	st3 := OpenStore(filepath.Join(t.TempDir(), "approvals.json"))
	r2 := rec("case-001", "GET", exp) // path /api/orders/123
	if err := st3.Save(r2); err != nil {
		t.Fatal(err)
	}
	if g, _ := st3.FindActive("request_replay", "case-001", "api.example.com", "GET", "/other"); g != nil {
		t.Error("path lain tidak boleh match approval path spesifik")
	}
	if g, _ := st3.FindActive("request_replay", "case-001", "api.example.com", "GET", "/api/orders/123"); g == nil {
		t.Error("path exact harus match")
	}
}

func TestStoreCorruptFileFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	if err := os.WriteFile(path, []byte("{bukan json"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := OpenStore(path)
	if _, err := st.Load(); err == nil {
		t.Error("file korup harus error (fail-closed), bukan direset")
	}
	if _, err := st.Active("c"); err == nil {
		t.Error("Active pada file korup harus error")
	}
	if err := st.Save(rec("c", "GET", time.Now().Add(time.Hour))); err == nil {
		t.Error("Save pada file korup harus error (tidak menimpa)")
	}
}

func TestStoreEmptyFileIsOK(t *testing.T) {
	st := OpenStore(filepath.Join(t.TempDir(), "tidak-ada.json"))
	recs, err := st.Load()
	if err != nil {
		t.Fatalf("store belum ada = kosong, bukan error: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("mau 0 record, dapat %d", len(recs))
	}
	if _, err := st.Active(""); err == nil {
		t.Error("case_id kosong harus error")
	}
}
