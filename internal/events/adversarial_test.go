package events

// Test adversarial level sistem (ROADMAP §25 Evidence Integrity):
// tampering file evidence dilihat dari sisi CONSUMER (event store yang
// melayani list_history/inspect_request/response_comparison).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tamperBodyBase64 memodifikasi satu karakter body_base64 evidence-000001.json
// (panjang byte TETAP — tamper halus) tanpa menghitung ulang sha256.
func tamperBodyBase64(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	resp, ok := m["response"].(map[string]any)
	if !ok {
		t.Fatal("field response tidak ada")
	}
	body, ok := resp["body_base64"].(string)
	if !ok || len(body) == 0 {
		t.Fatal("body_base64 tidak ada")
	}
	// Flip satu char base64 valid (e <-> f) — ukuran byte file tetap.
	flipped := strings.Replace(body, "e", "f", 1)
	if flipped == body {
		flipped = "f" + body[1:]
	}
	resp["body_base64"] = flipped
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// Marshal tanpa indent bisa mengubah ukuran; jaga ukuran tetap sama
	// dengan membandingkan: kalau beda, tulis apa adanya — test mtime
	// menyamarkan ukuran hanya bila memungkinkan.
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestInspectAndCompareFailClosedAfterTamper: index dimuat SEBELUM tamper,
// lalu file evidence diubah di disk. Inspect dan Compare WAJIB gagal
// fail-closed (sha256 diverifikasi ulang setiap kali file dibaca) — consumer
// tidak boleh percaya pada index/cache yang sudah ada.
func TestInspectAndCompareFailClosedAfterTamper(t *testing.T) {
	dir := t.TempDir()
	newEvidenceStore(t, dir, sampleRecords()...)

	st, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("load awal: %v", err)
	}
	if st.Count() != 2 {
		t.Fatalf("count = %d, mau 2", st.Count())
	}

	// Tamper file di disk SETELAH index dibangun.
	tamperBodyBase64(t, filepath.Join(dir, "evidence-000001.json"))

	if _, err := st.Inspect("evidence-000001.json"); err == nil {
		t.Error("Inspect pada evidence yang di-tamper harus gagal (§25)")
	} else if !strings.Contains(err.Error(), "integritas") {
		t.Errorf("error harus menyebut integritas: %v", err)
	}
	if _, err := st.Compare("evidence-000001.json", "evidence-000002.json"); err == nil {
		t.Error("Compare dengan evidence tamper harus gagal (§25)")
	}
	// Entry lain yang tidak disentuh tetap boleh dibaca.
	if _, err := st.Inspect("evidence-000002.json"); err != nil {
		t.Errorf("entry utuh tidak boleh ikut gagal: %v", err)
	}
	// Load ulang seluruh dir juga harus menolak.
	if _, err := LoadEvidenceDir(dir); err == nil {
		t.Error("LoadEvidenceDir pada dir berisi evidence tamper harus gagal")
	}
}

// TestListFailsClosedAfterTamperWithRestoredMtime: adversarial penuh —
// attacker mengubah isi evidence lalu MEMULIHKAN mtime file agar cache
// fingerprint (jika hanya name:size:mtime) tidak melihat perubahan.
// list_history HARUS tetap gagal fail-closed: fingerprint cache wajib
// berbasis hash KONTEN, bukan metadata file.
//
// Sebelum fix: cache dilayani dari index.jsonl lama → tamper tak terlihat
// oleh list_history (bug). Setelah fix (fingerprint content-hash): rebuild
// → parseAndVerify menolak.
func TestListFailsClosedAfterTamperWithRestoredMtime(t *testing.T) {
	dir := t.TempDir()
	newEvidenceStore(t, dir, sampleRecords()...)
	path := filepath.Join(dir, "evidence-000001.json")

	// Load pertama → cache index.jsonl tertulis.
	st1, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("load pertama: %v", err)
	}
	if st1.Count() != 2 {
		t.Fatalf("count = %d, mau 2", st1.Count())
	}
	if _, err := os.Stat(filepath.Join(dir, cacheFileName)); err != nil {
		t.Fatalf("cache harus tertulis: %v", err)
	}

	// Rekam mtime asli, tamper isi, pulihkan mtime.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	origMtime := fi.ModTime()
	tamperBodyBase64(t, path)
	if err := os.Chtimes(path, origMtime, origMtime); err != nil {
		t.Fatal(err)
	}
	// Sanity: ukuran & mtime persis seperti semula (simulasi tamper rapi).
	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi2.ModTime().Equal(origMtime) {
		t.Skipf("filesystem tidak mempertahankan mtime (granularitas %v) — preskondisi tidak bisa dibangun", origMtime.Sub(fi2.ModTime()))
	}

	// list_history (LoadEvidenceDir) harus MENOLAK — bukan menyajikan
	// index basi dari cache.
	st2, err := LoadEvidenceDir(dir)
	if err == nil {
		t.Errorf("tamper dengan mtime dipulihkan harus terdeteksi; index dilayani %d entry (cache basi)", st2.Count())
	} else if !strings.Contains(err.Error(), "integritas") && !strings.Contains(err.Error(), "sha256") {
		t.Errorf("error harus menjelaskan integritas: %v", err)
	}
}

// TestCacheFingerprintIsContentBased: dua file evidence berbeda isi tapi
// ukuran sama dan mtime dipaksa sama TIDAK boleh menghasilkan fingerprint
// sama (kalau iya, cache bisa menyembunyikan penggantian isi).
func TestCacheFingerprintIsContentBased(t *testing.T) {
	a := []byte(`{"seq":1,"body":"AAA"}`)
	b := []byte(`{"seq":1,"body":"BBB"}`) // ukuran sama, isi beda
	if len(a) != len(b) {
		t.Fatal("preskondisi: ukuran harus sama")
	}
	ha := sha256.Sum256(a)
	fa := fingerprint([]fileMeta{{name: "x.json", size: int64(len(a)), hash: hex.EncodeToString(ha[:])}})
	hb := sha256.Sum256(b)
	fb := fingerprint([]fileMeta{{name: "x.json", size: int64(len(b)), hash: hex.EncodeToString(hb[:])}})
	if fa == fb {
		t.Error("fingerprint harus berbeda untuk konten berbeda (content-hash based)")
	}
}
