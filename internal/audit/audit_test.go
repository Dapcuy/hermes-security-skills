package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendAndChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	e1, err := w.Append("hermes-security", "list-skills", map[string]any{"count": 7})
	if err != nil {
		t.Fatalf("Append 1 error: %v", err)
	}
	if e1.Seq != 1 || e1.PrevHash != GenesisPrevHash || e1.EntryHash == "" {
		t.Errorf("entry pertama salah: seq=%d prev=%q hash=%q", e1.Seq, e1.PrevHash, e1.EntryHash)
	}
	e2, err := w.Append("hermes-security", "abort", map[string]any{"case": "case-1"})
	if err != nil {
		t.Fatalf("Append 2 error: %v", err)
	}
	if e2.Seq != 2 {
		t.Errorf("seq kedua = %d, mau 2", e2.Seq)
	}
	if e2.PrevHash != e1.EntryHash {
		t.Errorf("prev_hash kedua = %q, mau %q (hash entry pertama)", e2.PrevHash, e1.EntryHash)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, mau 2", len(entries))
	}
	if entries[1].Action != "abort" || entries[1].Detail["case"] != "case-1" {
		t.Errorf("entry kedua tidak sesuai: %+v", entries[1])
	}
	if err := Verify(path); err != nil {
		t.Errorf("Verify error: %v", err)
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w1, err := Open(path)
	if err != nil {
		t.Fatalf("Open 1 error: %v", err)
	}
	if _, err := w1.Append("actor", "action-a", nil); err != nil {
		t.Fatalf("Append error: %v", err)
	}
	// Buka ulang: chain harus dilanjutkan, bukan mulai dari awal.
	w2, err := Open(path)
	if err != nil {
		t.Fatalf("Open 2 error: %v", err)
	}
	e, err := w2.Append("actor", "action-b", nil)
	if err != nil {
		t.Fatalf("Append 2 error: %v", err)
	}
	if e.Seq != 2 {
		t.Errorf("seq setelah reopen = %d, mau 2", e.Seq)
	}
	if err := Verify(path); err != nil {
		t.Errorf("Verify error: %v", err)
	}
}

func TestMissingFileIsFreshChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll file hilang harus ok (chain kosong), dapat %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %d, mau 0", len(entries))
	}
}

func TestTamperedEntryDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if _, err := w.Append("actor", "action-a", nil); err != nil {
		t.Fatalf("Append error: %v", err)
	}
	// Tamper: ubah action di baris pertama tanpa menghitung ulang hash.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baca file: %v", err)
	}
	tampered := strings.Replace(string(raw), `"action":"action-a"`, `"action":"tampered"`, 1)
	if tampered == string(raw) {
		t.Fatal("test bug: substitusi tidak terjadi")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("tulis file: %v", err)
	}
	if err := Verify(path); err == nil {
		t.Error("Verify harus mendeteksi entry yang diubah")
	}
}

func TestBrokenPrevHashDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, _ := Open(path)
	if _, err := w.Append("actor", "a1", nil); err != nil {
		t.Fatalf("Append error: %v", err)
	}
	if _, err := w.Append("actor", "a2", nil); err != nil {
		t.Fatalf("Append error: %v", err)
	}
	lines := strings.SplitN(string(mustRead(t, path)), "\n", 2)
	// Ganti prev_hash baris kedua.
	fake := strings.Replace(lines[1], `"prev_hash":"`, `"prev_hash":"deadbeef`, 1)
	content := lines[0] + "\n" + fake
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis: %v", err)
	}
	err := Verify(path)
	if err == nil || !strings.Contains(err.Error(), "prev_hash mismatch") {
		t.Errorf("Verify = %v, mau error prev_hash mismatch", err)
	}
}

func TestInvalidLineFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Baris JSON rusak.
	if err := os.WriteFile(path, []byte("bukan json\n"), 0o600); err != nil {
		t.Fatalf("tulis: %v", err)
	}
	if err := Verify(path); err == nil {
		t.Error("baris tidak valid harus error")
	}
	// Baris kosong di tengah.
	if err := os.WriteFile(path, []byte("{\"seq\":1,\"ts\":\"x\",\"actor\":\"a\",\"action\":\"b\",\"prev_hash\":\"\",\"entry_hash\":\"h\"}\n\n{\"seq\":2}\n"), 0o600); err != nil {
		t.Fatalf("tulis: %v", err)
	}
	if err := Verify(path); err == nil {
		t.Error("baris kosong di tengah harus error")
	}
}

func TestHashEntryDeterministic(t *testing.T) {
	e := Entry{
		Seq:      1,
		TS:       "2026-01-01T00:00:00Z",
		Actor:    "a",
		Action:   "b",
		Detail:   map[string]any{"x": 1, "y": "dua"},
		PrevHash: GenesisPrevHash,
	}
	h1, err := HashEntry(e)
	if err != nil {
		t.Fatalf("HashEntry error: %v", err)
	}
	h2, err := HashEntry(e)
	if err != nil {
		t.Fatalf("HashEntry error: %v", err)
	}
	if h1 != h2 {
		t.Error("hash harus deterministik")
	}
	e2 := e
	e2.Action = "berubah"
	h3, _ := HashEntry(e2)
	if h3 == h1 {
		t.Error("hash harus berubah saat isi berubah")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baca %s: %v", path, err)
	}
	return b
}
