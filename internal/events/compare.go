package events

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// Comparison hasil perbandingan dua evidence request/response.
type Comparison struct {
	EvidenceRefA string        `json:"evidence_ref_a"`
	EvidenceRefB string        `json:"evidence_ref_b"`
	StatusA      int           `json:"status_a"`
	StatusB      int           `json:"status_b"`
	Observations []Observation `json:"observations"`
}

// Compare membandingkan dua evidence request/response dan menghasilkan
// observations dengan struktur SAMA dengan kontrak validator-http
// (cmd/validator-http): type status_diff | header_diff | body_diff.
// Body diambil dari file evidence dan di-decode dari base64 sebelum
// dibandingkan. Read-only: kedua file tidak pernah dimodifikasi.
func (s *Store) Compare(refA, refB string) (*Comparison, error) {
	recA, err := s.loadVerified(refA)
	if err != nil {
		return nil, err
	}
	recB, err := s.loadVerified(refB)
	if err != nil {
		return nil, err
	}

	obs := compareRecords(recA.coreRecord, recB.coreRecord)
	if obs == nil {
		obs = []Observation{} // JSON array kosong, bukan null (kontrak validator)
	}
	return &Comparison{
		EvidenceRefA: mustSafeRefName(refA),
		EvidenceRefB: mustSafeRefName(refB),
		StatusA:      recA.Response.Status,
		StatusB:      recB.Response.Status,
		Observations: obs,
	}, nil
}

// compareRecords logika inti perbandingan — dipisahkan agar testable
// langsung dari record tanpa file.
func compareRecords(a, b coreRecord) []Observation {
	var obs []Observation
	if a.Response.Status != b.Response.Status {
		obs = append(obs, Observation{
			Type:   "status_diff",
			Detail: fmt.Sprintf("status: %d -> %d", a.Response.Status, b.Response.Status),
		})
	}
	ha := normalizeHeaders(a.Response.Headers)
	hb := normalizeHeaders(b.Response.Headers)
	for _, k := range sortedUnionKeys(ha, hb) {
		va, ina := ha[k]
		vb, inb := hb[k]
		switch {
		case ina && !inb:
			obs = append(obs, Observation{
				Type:   "header_diff",
				Detail: fmt.Sprintf("header %s: hanya di response_a (nilai %q)", k, va),
			})
		case !ina && inb:
			obs = append(obs, Observation{
				Type:   "header_diff",
				Detail: fmt.Sprintf("header %s: hanya di response_b (nilai %q)", k, vb),
			})
		case va != vb:
			obs = append(obs, Observation{
				Type:   "header_diff",
				Detail: fmt.Sprintf("header %s: %q -> %q", k, va, vb),
			})
		}
	}
	bodyA := mustDecodeBytes(a.Response.BodyBase64)
	bodyB := mustDecodeBytes(b.Response.BodyBase64)
	if !equalBytes(bodyA, bodyB) {
		obs = append(obs, Observation{
			Type:   "body_diff",
			Detail: fmt.Sprintf("body berbeda: %d byte -> %d byte", len(bodyA), len(bodyB)),
		})
	}
	return obs
}

// loadVerified membaca + memverifikasi satu evidence file dari store.
func (s *Store) loadVerified(evidenceRef string) (rawRecord, error) {
	ref, err := safeRef(evidenceRef)
	if err != nil {
		return rawRecord{}, err
	}
	if _, ok := s.lookup(ref); !ok {
		return rawRecord{}, fmt.Errorf("%w: %s (bukan bagian dari index %s)", ErrNotFound, ref, s.dir)
	}
	data, err := os.ReadFile(filepath.Join(s.dir, ref))
	if err != nil {
		if os.IsNotExist(err) {
			return rawRecord{}, fmt.Errorf("%w: file hilang: %s", ErrNotFound, ref)
		}
		return rawRecord{}, fmt.Errorf("events: baca %s: %w", ref, err)
	}
	return parseAndVerify(data)
}

// mustSafeRefName memvalidasi ref untuk keperluan output (panics tidak —
// ref dari loadVerified sudah lolos safeRef; ini hanya normalisasi ulang).
func mustSafeRefName(ref string) string {
	r, err := safeRef(ref)
	if err != nil {
		return ""
	}
	return r
}

// normalizeHeaders menyeragamkan header evidence (map[string][]string) ke
// map lowercase key -> nilai gabungan (multi-value digabung ", ") agar
// perbandingan case-insensitive seperti HTTP header.
func normalizeHeaders(h map[string][]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[strings.ToLower(k)] = strings.Join(vals, ", ")
	}
	return out
}

// sortedUnionKeys semua key dari a dan b, terurut deterministik.
func sortedUnionKeys(a, b map[string]string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	keys := make([]string, 0, len(a)+len(b))
	for k := range a {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// mustDecodeBytes decode base64 evidence body; string kosong = slice kosong.
// Input berasal dari evidence yang sha256-nya sudah terverifikasi, jadi
// kegagalan decode tidak diharapkan; fallback aman = raw string.
func mustDecodeBytes(b64 string) []byte {
	if b64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return []byte(b64)
	}
	return raw
}

func equalBytes(a, b []byte) bool { return reflect.DeepEqual(a, b) }

// ---------------------------------------------------------------- JSON diff

// JSONDiff membandingkan dua nilai JSON apa pun (flatten key-path) dan
// menghasilkan observations type "json_diff" — logika yang sama dengan
// validator-json (cmd/validator-json), dipakai ulang oleh MCP tool json_diff.
// Root dilambangkan "$"; array ditandai "$[i]".
func JSONDiff(a, b any) []Observation {
	var obs []Observation
	diffJSON("$", a, b, &obs)
	if obs == nil {
		return []Observation{}
	}
	return obs
}

func diffJSON(path string, a, b any, obs *[]Observation) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		for _, k := range sortedStringKeys(am, bm) {
			kp := path + "." + k
			va, ina := am[k]
			vb, inb := bm[k]
			switch {
			case ina && !inb:
				addObs(obs, kp+": hanya di json_a ("+formatVal(va)+")")
			case !ina && inb:
				addObs(obs, kp+": hanya di json_b ("+formatVal(vb)+")")
			default:
				diffJSON(kp, va, vb, obs)
			}
		}
		return
	}
	aa, aarr := a.([]any)
	ba, barr := b.([]any)
	if aarr && barr {
		if len(aa) != len(ba) {
			addObs(obs, fmt.Sprintf("%s: panjang array %d -> %d", path, len(aa), len(ba)))
		}
		n := len(aa)
		if len(ba) < n {
			n = len(ba)
		}
		for i := 0; i < n; i++ {
			diffJSON(fmt.Sprintf("%s[%d]", path, i), aa[i], ba[i], obs)
		}
		return
	}
	if !reflect.DeepEqual(a, b) {
		addObs(obs, path+": "+formatVal(a)+" -> "+formatVal(b))
	}
}

func addObs(obs *[]Observation, detail string) {
	*obs = append(*obs, Observation{Type: "json_diff", Detail: detail})
}

func sortedStringKeys(a, b map[string]any) []string {
	seen := make(map[string]bool, len(a)+len(b))
	keys := make([]string, 0, len(a)+len(b))
	for k := range a {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func formatVal(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
