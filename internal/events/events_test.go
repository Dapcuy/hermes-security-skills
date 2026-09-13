package events

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hermes-security-skills/internal/proxycore"
)

// newEvidenceStore membuat evidence fixture via proxycore.EvidenceStore —
// format file dijamin identik dengan yang ditulis hermes-proxy. Store
// dikembalikan agar test bisa lanjut menulis dengan seq yang berlanjut.
func newEvidenceStore(t *testing.T, dir string, recs ...proxycore.EvidenceRecord) *proxycore.EvidenceStore {
	t.Helper()
	es, err := proxycore.NewEvidenceStore(dir)
	if err != nil {
		t.Fatalf("NewEvidenceStore: %v", err)
	}
	for _, rec := range recs {
		if _, _, err := es.Write(rec); err != nil {
			t.Fatalf("Write evidence: %v", err)
		}
	}
	return es
}

// headerValue nilai pertama sebuah header dari map evidence.
func headerValue(h map[string][]string, name string) string {
	vals, ok := h[name]
	if !ok || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func sampleRecords() []proxycore.EvidenceRecord {
	return []proxycore.EvidenceRecord{
		{
			Request: proxycore.EvidenceRequest{
				Method:       "GET",
				URL:          "http://localhost:8901/orders/1",
				Headers:      proxycore.RedactHeaders(http.Header{"Authorization": {"Bearer x"}}),
				BodyEncoding: "base64",
			},
			Response: proxycore.EvidenceResponse{
				Status:       200,
				Headers:      proxycore.RedactHeaders(http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"s=1"}}),
				BodyBase64:   base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)),
				BodyEncoding: "base64",
			},
		},
		{
			Request: proxycore.EvidenceRequest{
				Method:       "POST",
				URL:          "http://localhost:8901/orders/1/status",
				Headers:      proxycore.RedactHeaders(http.Header{}),
				BodyBase64:   base64.StdEncoding.EncodeToString([]byte(`{"state":"shipped"}`)),
				BodyEncoding: "base64",
			},
			Response: proxycore.EvidenceResponse{
				Status:       404,
				Headers:      proxycore.RedactHeaders(http.Header{"Content-Type": {"application/json"}, "X-Extra": {"only-b"}}),
				BodyBase64:   base64.StdEncoding.EncodeToString([]byte(`{"error":"not found"}`)),
				BodyEncoding: "base64",
			},
		},
	}
}

func TestLoadEvidenceDirBuildsIndex(t *testing.T) {
	dir := t.TempDir()
	newEvidenceStore(t, dir, sampleRecords()...)

	st, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("LoadEvidenceDir: %v", err)
	}
	if st.Count() != 2 {
		t.Fatalf("count = %d, mau 2", st.Count())
	}
	entries := st.Entries()
	if entries[0].Seq != 1 || entries[1].Seq != 2 {
		t.Errorf("seq tidak urut menaik: %+v", entries)
	}
	if entries[0].Method != "GET" || entries[0].URL != "http://localhost:8901/orders/1" || entries[0].Status != 200 {
		t.Errorf("entry[0] salah: %+v", entries[0])
	}
	if entries[1].Method != "POST" || entries[1].Status != 404 {
		t.Errorf("entry[1] salah: %+v", entries[1])
	}
	if entries[0].EvidenceRef != "evidence-000001.json" {
		t.Errorf("ref = %q", entries[0].EvidenceRef)
	}
	if len(entries[0].SHA256) != 64 {
		t.Errorf("sha256 harus hex 64 char: %q", entries[0].SHA256)
	}
	if entries[0].TS == "" {
		t.Error("ts (captured_at) wajib terisi")
	}
}

func TestListFilters(t *testing.T) {
	dir := t.TempDir()
	newEvidenceStore(t, dir, sampleRecords()...)
	st, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("LoadEvidenceDir: %v", err)
	}

	// Tanpa filter.
	if got := st.List(ListFilter{}); len(got) != 2 {
		t.Errorf("tanpa filter mau 2, dapat %d", len(got))
	}
	// Filter URL substring.
	got := st.List(ListFilter{URLSubstring: "ORDERS"}) // case-insensitive
	if len(got) != 2 {
		t.Errorf("url_substring case-insensitive mau 2, dapat %d", len(got))
	}
	got = st.List(ListFilter{URLSubstring: "orders/1/status"})
	if len(got) != 1 || got[0].Method != "POST" {
		t.Errorf("url_substring filter salah: %+v", got)
	}
	// Filter method.
	got = st.List(ListFilter{Method: "post"}) // case-insensitive
	if len(got) != 1 || got[0].Status != 404 {
		t.Errorf("method filter salah: %+v", got)
	}
	// Filter status_min.
	got = st.List(ListFilter{StatusMin: 300})
	if len(got) != 1 || got[0].Status != 404 {
		t.Errorf("status_min filter salah: %+v", got)
	}
	// Limit: entri terbaru yang dipertahankan, urutan tetap menaik.
	got = st.List(ListFilter{Limit: 1})
	if len(got) != 1 || got[0].Seq != 2 {
		t.Errorf("limit harus ambil terbaru: %+v", got)
	}
	// Kombinasi tanpa hasil.
	got = st.List(ListFilter{Method: "DELETE"})
	if got == nil || len(got) != 0 {
		t.Errorf("tanpa hasil harus slice kosong (bukan nil): %v", got)
	}
}

func TestInspect(t *testing.T) {
	dir := t.TempDir()
	newEvidenceStore(t, dir, sampleRecords()...)
	st, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("LoadEvidenceDir: %v", err)
	}

	d, err := st.Inspect("evidence-000001.json")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if d.Seq != 1 || d.EvidenceRef != "evidence-000001.json" {
		t.Errorf("detail identitas salah: %+v", d)
	}
	// Header tetap ter-redaksi seperti di file (§24/§25).
	if got := headerValue(d.Request.Headers, "Authorization"); got != proxycore.RedactedValue {
		t.Errorf("Authorization = %q, mau %q", got, proxycore.RedactedValue)
	}
	if got := headerValue(d.Response.Headers, "Set-Cookie"); got != proxycore.RedactedValue {
		t.Errorf("Set-Cookie = %q, mau %q", got, proxycore.RedactedValue)
	}
	if d.Response.Status != 200 {
		t.Errorf("status = %d", d.Response.Status)
	}
	if d.Response.Body != `{"ok":true}` || d.Response.BodyEncoding != "utf-8" {
		t.Errorf("body decode salah: %q (%s)", d.Response.Body, d.Response.BodyEncoding)
	}
	if d.Provenance["component"] != "hermes-proxy" {
		t.Errorf("provenance salah: %v", d.Provenance)
	}

	// Binary body tetap base64 (encoding "base64").
	dir2 := t.TempDir()
	newEvidenceStore(t, dir2, proxycore.EvidenceRecord{
		Request:  proxycore.EvidenceRequest{Method: "GET", URL: "http://x/y", Headers: proxycore.RedactHeaders(http.Header{}), BodyEncoding: "base64"},
		Response: proxycore.EvidenceResponse{Status: 200, Headers: proxycore.RedactHeaders(http.Header{}), BodyBase64: base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x10}), BodyEncoding: "base64"},
	})
	st2, err := LoadEvidenceDir(dir2)
	if err != nil {
		t.Fatalf("LoadEvidenceDir binary: %v", err)
	}
	d2, err := st2.Inspect("evidence-000001.json")
	if err != nil {
		t.Fatalf("Inspect binary: %v", err)
	}
	if d2.Response.BodyEncoding != "base64" {
		t.Errorf("binary body harus encoding base64, dapat %q", d2.Response.BodyEncoding)
	}

	// Fail-closed: ref aneh / tidak ada.
	for _, bad := range []string{"", "../evidence-000001.json", "sub/evidence-000001.json", "secret.json", "evidence-999999.json"} {
		if _, err := st.Inspect(bad); err == nil {
			t.Errorf("Inspect(%q) harus error", bad)
		}
	}
	if _, err := st.Inspect("evidence-999999.json"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ref tidak ada harus ErrNotFound, dapat %v", err)
	}
}

func TestCompareProducesValidatorCompatibleObservations(t *testing.T) {
	dir := t.TempDir()
	newEvidenceStore(t, dir, sampleRecords()...)
	st, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("LoadEvidenceDir: %v", err)
	}

	cmp, err := st.Compare("evidence-000001.json", "evidence-000002.json")
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if cmp.StatusA != 200 || cmp.StatusB != 404 {
		t.Errorf("status salah: %d -> %d", cmp.StatusA, cmp.StatusB)
	}
	types := map[string]int{}
	for _, o := range cmp.Observations {
		types[o.Type]++
	}
	// response_a: Content-Type + Set-Cookie; response_b: Content-Type + X-Extra
	// → 2 header_diff (set-cookie hanya di a, x-extra hanya di b).
	if types["status_diff"] != 1 || types["header_diff"] != 2 || types["body_diff"] != 1 {
		t.Errorf("observations salah: %#v", cmp.Observations)
	}
	for _, o := range cmp.Observations {
		if o.Detail == "" {
			t.Errorf("observation tanpa detail: %#v", o)
		}
	}
	// Detail status_diff format sama dengan validator-http.
	for _, o := range cmp.Observations {
		if o.Type == "status_diff" && o.Detail != "status: 200 -> 404" {
			t.Errorf("detail status_diff = %q, mau %q", o.Detail, "status: 200 -> 404")
		}
		if o.Type == "body_diff" && !strings.Contains(o.Detail, "byte ->") {
			t.Errorf("detail body_diff = %q", o.Detail)
		}
	}

	// Identik = tanpa observation (array kosong).
	rec := sampleRecords()[0]
	dir2 := t.TempDir()
	newEvidenceStore(t, dir2, rec, rec)
	st2, err := LoadEvidenceDir(dir2)
	if err != nil {
		t.Fatalf("LoadEvidenceDir: %v", err)
	}
	cmp2, err := st2.Compare("evidence-000001.json", "evidence-000002.json")
	if err != nil {
		t.Fatalf("Compare identik: %v", err)
	}
	if cmp2.Observations == nil || len(cmp2.Observations) != 0 {
		t.Errorf("identik harus observations kosong (bukan nil): %#v", cmp2.Observations)
	}

	// Fail-closed.
	if _, err := st.Compare("evidence-000001.json", "nope.json"); err == nil {
		t.Error("ref B tidak ada harus error")
	}
}

func TestLoadEvidenceDirIntegrityFailClosed(t *testing.T) {
	dir := t.TempDir()
	newEvidenceStore(t, dir, sampleRecords()...)
	path := filepath.Join(dir, "evidence-000001.json")

	// Tamper: ubah status tanpa menghitung ulang sha256 → load harus gagal.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["sha256"] = strings.Repeat("0", 64)
	tampered, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvidenceDir(dir); err == nil {
		t.Error("evidence yang dimodifikasi harus gagal load (§25 Evidence Integrity)")
	} else if !strings.Contains(err.Error(), "integritas") {
		t.Errorf("error harus menjelaskan integritas: %v", err)
	}
}

func TestLoadEvidenceDirEmptyAndMissing(t *testing.T) {
	// Dir kosong (belum ada evidence) = index kosong, bukan error.
	st, err := LoadEvidenceDir(t.TempDir())
	if err != nil {
		t.Fatalf("dir kosong harus ok: %v", err)
	}
	if st.Count() != 0 {
		t.Errorf("count = %d, mau 0", st.Count())
	}
	// Dir tidak ada = error (fail-closed — salah flag jelas terlihat).
	if _, err := LoadEvidenceDir(filepath.Join(t.TempDir(), "tidak-ada")); err == nil {
		t.Error("dir tidak ada harus error")
	}
}

func TestCacheReuseAndRebuild(t *testing.T) {
	dir := t.TempDir()
	es := newEvidenceStore(t, dir, sampleRecords()...)

	st1, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("load pertama: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, cacheFileName)); err != nil {
		t.Fatalf("cache harus tertulis: %v", err)
	}
	// Load kedua: fingerprint sama → cache dipakai; hasil harus identik.
	st2, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("load kedua: %v", err)
	}
	if st2.Count() != st1.Count() {
		t.Errorf("count cache = %d, mau %d", st2.Count(), st1.Count())
	}

	// Tambah evidence (seq berlanjut) → fingerprint berubah → rebuild (3 entri).
	if _, _, err := es.Write(sampleRecords()[0]); err != nil {
		t.Fatal(err)
	}
	st3, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("load ketiga: %v", err)
	}
	if st3.Count() != 3 {
		t.Errorf("setelah tambah evidence mau 3, dapat %d", st3.Count())
	}

	// Cache korup → rebuild, bukan error.
	if err := os.WriteFile(filepath.Join(dir, cacheFileName), []byte("korup{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	st4, err := LoadEvidenceDir(dir)
	if err != nil {
		t.Fatalf("cache korup harus di-rebuild: %v", err)
	}
	if st4.Count() != 3 {
		t.Errorf("count = %d, mau 3", st4.Count())
	}
}

func TestJSONDiff(t *testing.T) {
	a := map[string]any{"x": 1, "y": "sama", "list": []any{1, 2}, "z": map[string]any{"a": true}}
	b := map[string]any{"x": 2, "list": []any{1, 2, 3}, "w": "baru", "z": map[string]any{"a": true}}
	obs := JSONDiff(a, b)
	details := make([]string, 0, len(obs))
	for _, o := range obs {
		if o.Type != "json_diff" {
			t.Errorf("type = %s, mau json_diff", o.Type)
		}
		details = append(details, o.Detail)
	}
	joined := strings.Join(details, "|")
	for _, want := range []string{"$.x: 1 -> 2", "$.y: hanya di json_a", "$.w: hanya di json_b", "$.list: panjang array 2 -> 3"} {
		if !strings.Contains(joined, want) {
			t.Errorf("detail harus mengandung %q: %q", want, joined)
		}
	}

	// Identik = kosong.
	if got := JSONDiff(map[string]any{"a": 1}, map[string]any{"a": 1}); len(got) != 0 {
		t.Errorf("identik harus kosong: %#v", got)
	}
	// Nil (JSON null) vs nilai.
	obs = JSONDiff(nil, "x")
	if len(obs) != 1 || obs[0].Detail != "$: null -> \"x\"" {
		t.Errorf("diff null salah: %#v", obs)
	}
}
