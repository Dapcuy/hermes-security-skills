package approval

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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

// ---------------------------------------------------------------- adversarial

// TestStoreConsumeConcurrencyExactBudget: 50 goroutine menyerang Consume()
// bersamaan pada approval max_requests=5. Budget harus TERPAKAI TEPAT 5 —
// tidak boleh over-consume (bocor) maupun under-consume (lost update).
func TestStoreConsumeConcurrencyExactBudget(t *testing.T) {
	const maxReq = 5
	const attackers = 50
	path := filepath.Join(t.TempDir(), "approvals.json")
	st := OpenStore(path)
	exp := time.Now().Add(time.Hour).UTC()
	r := rec("case-race", "GET", exp)
	r.MaxRequests = maxReq
	if err := st.Save(r); err != nil {
		t.Fatal(err)
	}
	recs, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	id := recs[0].ID

	var okCount int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < attackers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := st.Consume(id); err == nil {
				atomic.AddInt64(&okCount, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if okCount != maxReq {
		t.Errorf("Consume sukses = %d, mau TEPAT %d (max_requests)", okCount, maxReq)
	}
	// State akhir di disk harus konsisten: Used == 5.
	st2 := OpenStore(path)
	got, err := st2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Used != maxReq {
		t.Errorf("Used di disk = %d, mau %d", got[0].Used, maxReq)
	}
	// Budget habis: consume ke-51 harus ErrExhausted, bukan error lain.
	if err := st2.Consume(id); !errors.Is(err, ErrExhausted) {
		t.Errorf("consume setelah race = %v, mau ErrExhausted", err)
	}
}

// TestStoreCraftedExpiredNeverActive: file approvals.json di-craft manual
// dengan expires_at di masa lalu — tidak boleh pernah aktif walau record
// tampak valid dan file ditulis ulang berkali-kali.
func TestStoreCraftedExpiredNeverActive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	craft := fmt.Sprintf(`[
  {
    "id": "craftdeadbeef",
    "case_id": "case-craft",
    "capability": "request_replay",
    "host": "api.example.com",
    "method": "GET",
    "path": "*",
    "max_requests": 99,
    "expires_at": %q,
    "risk": "low",
    "created_at": %q,
    "used": 0
  }
]`, past, past)
	if err := os.WriteFile(path, []byte(craft), 0o600); err != nil {
		t.Fatal(err)
	}
	st := OpenStore(path)
	// Ulangi beberapa kali: menulis ulang file (craft ulang) tidak boleh
	// menghidupkan record kadaluarsa.
	for i := 0; i < 3; i++ {
		got, err := st.FindActive("request_replay", "case-craft", "api.example.com", "GET", "/x")
		if err != nil {
			t.Fatalf("FindActive iterasi %d: %v", i, err)
		}
		if got != nil {
			t.Fatalf("iterasi %d: record expired tidak boleh aktif: %+v", i, got)
		}
		act, err := st.Active("case-craft")
		if err != nil {
			t.Fatal(err)
		}
		if len(act) != 0 {
			t.Errorf("iterasi %d: Active = %d, mau 0", i, len(act))
		}
		if err := st.Consume("craftdeadbeef"); !errors.Is(err, ErrExpired) {
			t.Errorf("iterasi %d: Consume expired = %v, mau ErrExpired", i, err)
		}
		// Craft ulang file (simulasi attacker menulis ulang).
		if err := os.WriteFile(path, []byte(craft), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestStoreCraftedRevokedAndExpiredNeverActive: record revoked:true +
// expired di file yang di-craft → FindActive tidak boleh mengembalikan.
func TestStoreCraftedRevokedAndExpiredNeverActive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	past := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	craft := fmt.Sprintf(`[
  {
    "id": "craftrevoked01",
    "case_id": "case-craft",
    "capability": "request_replay",
    "host": "api.example.com",
    "method": "POST",
    "path": "/api/orders/123",
    "max_requests": 10,
    "expires_at": %q,
    "risk": "medium",
    "created_at": %q,
    "used": 0,
    "revoked": true,
    "revoked_at": %q,
    "revoke_reason": "revoked-by-abort"
  }
]`, past, past, past)
	if err := os.WriteFile(path, []byte(craft), 0o600); err != nil {
		t.Fatal(err)
	}
	st := OpenStore(path)
	got, err := st.FindActive("request_replay", "case-craft", "api.example.com", "POST", "/api/orders/123")
	if err != nil {
		t.Fatalf("FindActive: %v", err)
	}
	if got != nil {
		t.Errorf("record revoked+expired tidak boleh aktif: %+v", got)
	}
	if err := st.Consume("craftrevoked01"); !errors.Is(err, ErrRevoked) {
		t.Errorf("Consume revoked = %v, mau ErrRevoked", err)
	}
}

// TestStoreTamperedDuplicateIDFailClosed: file di-tamper (JSON valid tapi
// id duplikat) → seluruh operasi store harus fail-closed dengan error,
// bukan memilih record secara diam-diam.
//
// Keputusan desain (terdokumentasi): duplikat id pada store adalah bukti
// tampering (Save selalu menolak id duplikat), jadi readLocked menolak
// file semacam ini total — fail-closed, BUKAN dedup deterministik. Alasan:
// dedup memberi attacker jalur memilih record mana yang "menang" (mis.
// menggandakan record dengan Used=0), sedangkan error membuat tampering
// terlihat di semua entry point (Load/Active/FindActive/Consume).
func TestStoreTamperedDuplicateIDFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	craft := fmt.Sprintf(`[
  {"id":"dup01","case_id":"c","capability":"request_replay","host":"h","method":"GET","path":"*","max_requests":5,"expires_at":%q,"risk":"low","created_at":%q,"used":4},
  {"id":"dup01","case_id":"c","capability":"request_replay","host":"h","method":"GET","path":"*","max_requests":5,"expires_at":%q,"risk":"low","created_at":%q,"used":0}
]`, exp, exp, exp, exp)
	if err := os.WriteFile(path, []byte(craft), 0o600); err != nil {
		t.Fatal(err)
	}
	st := OpenStore(path)
	if _, err := st.Load(); err == nil {
		t.Error("Load pada file dengan id duplikat harus error (fail-closed)")
	}
	if got, err := st.FindActive("request_replay", "c", "h", "GET", "/x"); err == nil && got != nil {
		t.Errorf("FindActive pada id duplikat harus gagal/nil, dapat %+v (err=%v)", got, err)
	} else if err == nil {
		t.Error("FindActive pada id duplikat harus error, bukan nil,nil")
	}
	if err := st.Consume("dup01"); err == nil {
		t.Error("Consume pada id duplikat harus error (fail-closed)")
	}
	// Save juga harus tetap gagal (tidak menimpa file tamper diam-diam).
	if err := st.Save(rec("c2", "GET", time.Now().Add(time.Hour))); err == nil {
		t.Error("Save pada file korup harus error")
	}
}

// TestStoreTamperedNegativeUsedFailClosed: record dengan used negatif
// memberi budget ekstra saat di-craft manual — harus ditolak fail-closed.
func TestStoreTamperedNegativeUsedFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	craft := fmt.Sprintf(`[
  {"id":"neg01","case_id":"c","capability":"request_replay","host":"h","method":"GET","path":"*","max_requests":1,"expires_at":%q,"risk":"low","created_at":%q,"used":-1000}
]`, exp, exp)
	if err := os.WriteFile(path, []byte(craft), 0o600); err != nil {
		t.Fatal(err)
	}
	st := OpenStore(path)
	if _, err := st.Load(); err == nil {
		t.Error("used negatif harus ditolak (bypass budget via tampering)")
	}
	if err := st.Consume("neg01"); err == nil {
		t.Error("Consume pada used negatif harus error")
	}
}

// TestStoreConsumeRaceWithRevoke: kill switch revoke() dijalankan saat 10
// goroutine menunggu/berlomba Consume. Jaminan: SETELAH RevokeCase kembali,
// tidak ada satu pun Consume yang berhasil — eksekusi pasca-revoke nihil.
// (Consume yang selesai SEBELUM revoke selesai adalah eksekusi yang sudah
// berjalan sebelum kill switch aktif — tidak terhindarkan pada model ini;
// lihat laporan adversarial.)
func TestStoreConsumeRaceWithRevoke(t *testing.T) {
	const maxReq = 100
	path := filepath.Join(t.TempDir(), "approvals.json")
	st := OpenStore(path)
	exp := time.Now().Add(time.Hour).UTC()
	r := rec("case-abort", "GET", exp)
	r.MaxRequests = maxReq
	if err := st.Save(r); err != nil {
		t.Fatal(err)
	}
	recs, _ := st.Load()
	id := recs[0].ID

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := st.Consume(id); err != nil {
					return // revoked/expired/habis — goroutine berhenti
				}
			}
		}()
	}
	// Beri kesempatan goroutine mengonsumsi sebagian, lalu kill switch.
	time.Sleep(5 * time.Millisecond)
	revokedAt := time.Now().UTC()
	n, err := st.RevokeCase("case-abort", ReasonRevokedByAbort)
	if err != nil {
		t.Fatalf("RevokeCase: %v", err)
	}
	if n != 1 {
		t.Fatalf("mau 1 record dicabut, dapat %d", n)
	}
	close(stop)
	wg.Wait()

	// Setelah revoke kembali: SEMUA Consume harus gagal.
	for i := 0; i < 20; i++ {
		if err := st.Consume(id); !errors.Is(err, ErrRevoked) {
			t.Fatalf("Consume pasca-revoke = %v, mau ErrRevoked", err)
		}
	}
	// Record final: revoked dengan timestamp revoke yang wajar.
	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].Revoked || got[0].RevokeReason != ReasonRevokedByAbort {
		t.Errorf("record final tidak revoked: %+v", got[0])
	}
	if got[0].RevokedAt.Before(revokedAt.Add(-time.Second)) || got[0].RevokedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("revoked_at %v di luar rentang wajar [%v..]", got[0].RevokedAt, revokedAt)
	}
	if got[0].Used > maxReq {
		t.Errorf("Used = %d melebihi max_requests %d", got[0].Used, maxReq)
	}
}
