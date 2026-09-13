package yamlmini

import (
	"reflect"
	"strings"
	"testing"
)

const registryFixture = `
# Komentar header
version: 1

fallback_semantics: fail-closed

capabilities:

  inspect_request:
    risk: low
    default_provider: proxy
    requires_scope: true
    requires_network: false

  request_replay:
    risk: medium
    default_provider: proxy
    requires_scope: true
    requires_network: true
    requires_approval: conditional
`

func TestParseRegistryFixture(t *testing.T) {
	doc, err := Parse([]byte(registryFixture))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if got := doc["version"]; got != 1 {
		t.Errorf("version = %v (%T), mau 1 (int)", got, got)
	}
	if got := doc["fallback_semantics"]; got != "fail-closed" {
		t.Errorf("fallback_semantics = %v, mau fail-closed", got)
	}
	caps, ok := doc["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities bukan map: %T", doc["capabilities"])
	}
	if len(caps) != 2 {
		t.Fatalf("len(capabilities) = %d, mau 2", len(caps))
	}
	ir, ok := caps["inspect_request"].(map[string]any)
	if !ok {
		t.Fatalf("inspect_request bukan map")
	}
	if ir["risk"] != "low" {
		t.Errorf("risk = %v, mau low", ir["risk"])
	}
	if ir["requires_scope"] != true {
		t.Errorf("requires_scope = %v (%T), mau true (bool)", ir["requires_scope"], ir["requires_scope"])
	}
	if ir["requires_network"] != false {
		t.Errorf("requires_network = %v (%T), mau false (bool)", ir["requires_network"], ir["requires_network"])
	}
	rr, ok := caps["request_replay"].(map[string]any)
	if !ok {
		t.Fatalf("request_replay bukan map")
	}
	if rr["requires_approval"] != "conditional" {
		t.Errorf("requires_approval = %v, mau conditional", rr["requires_approval"])
	}
}

func TestParseEmptyAndCommentsOnly(t *testing.T) {
	for _, src := range []string{"", "\n\n", "# hanya komentar\n"} {
		doc, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", src, err)
		}
		if len(doc) != 0 {
			t.Errorf("Parse(%q) = %v, mau map kosong", src, doc)
		}
	}
}

func TestParseSequences(t *testing.T) {
	src := `
classes:
  low:
    action: automatic
    examples:
      - passive analysis
      - metadata GET
      - 'quoted # not comment'
allowed: [a, b, c]
empty: []
quoted: "double quoted"
single: 'it''s'
trailing: value   # komentar trailing
`
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	classes, ok := doc["classes"].(map[string]any)
	if !ok {
		t.Fatalf("classes bukan map: %T", doc["classes"])
	}
	low, ok := classes["low"].(map[string]any)
	if !ok {
		t.Fatalf("classes.low bukan map")
	}
	ex, ok := low["examples"].([]any)
	if !ok {
		t.Fatalf("examples bukan seq: %T", low["examples"])
	}
	want := []any{"passive analysis", "metadata GET", "quoted # not comment"}
	if !reflect.DeepEqual(ex, want) {
		t.Errorf("examples = %#v, mau %#v", ex, want)
	}
	al, ok := doc["allowed"].([]any)
	if !ok {
		t.Fatalf("allowed bukan seq (flow): %T", doc["allowed"])
	}
	if !reflect.DeepEqual(al, []any{"a", "b", "c"}) {
		t.Errorf("allowed = %#v", al)
	}
	if v, ok := doc["empty"].([]any); !ok || len(v) != 0 {
		t.Errorf("empty = %#v, mau seq kosong", doc["empty"])
	}
	if got := doc["quoted"]; got != "double quoted" {
		t.Errorf("quoted = %v", got)
	}
	if got := doc["single"]; got != "it's" {
		t.Errorf("single = %v, mau it's", got)
	}
	if got := doc["trailing"]; got != "value" {
		t.Errorf("trailing = %v, mau value", got)
	}
}

func TestParseSeqOfMaps(t *testing.T) {
	src := `
items:
  - name: a
    count: 1
  - name: b
    count: 2
`
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	items, ok := doc["items"].([]any)
	if !ok {
		t.Fatalf("items bukan seq: %T", doc["items"])
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d, mau 2", len(items))
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("items[0] bukan map: %T", items[0])
	}
	if first["name"] != "a" || first["count"] != 1 {
		t.Errorf("items[0] = %#v", first)
	}
}

func TestParseCompactSeqSameIndent(t *testing.T) {
	// Bentuk YAML legal: seq pada indent sama dengan key-nya.
	src := "allowed_hosts:\n- example.com\n- '*.example.com'\n"
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	got, ok := doc["allowed_hosts"].([]any)
	if !ok {
		t.Fatalf("allowed_hosts bukan seq: %T", doc["allowed_hosts"])
	}
	if !reflect.DeepEqual(got, []any{"example.com", "*.example.com"}) {
		t.Errorf("allowed_hosts = %#v", got)
	}
}

func TestParseNegativeInt(t *testing.T) {
	doc, err := Parse([]byte("n: -5\np: 42\nnotint: 1.5\n"))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if doc["n"] != -5 || doc["p"] != 42 {
		t.Errorf("int salah: n=%v p=%v", doc["n"], doc["p"])
	}
	if doc["notint"] != "1.5" {
		// Float tidak ada di subset -> tetap string.
		t.Errorf("notint = %v (%T), mau string 1.5", doc["notint"], doc["notint"])
	}
}

func TestParseFailClosed(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"tab indentasi", "a:\n\tb: 1\n"},
		{"key duplikat", "a: 1\na: 2\n"},
		{"indentasi tidak konsisten", "a: 1\n  b: 2\n"},
		{"flow map ditolak", "a: {b: 1}\n"},
		{"flow seq tak ditutup", "a: [1, 2\n"},
		{"string tidak ditutup", `a: "unclosed` + "\n"},
		{"baris mapping tidak valid", "hanya_teks_tanpa_colon\n"},
		{"dokumen ganda", "a: 1\n---\nb: 2\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.src)); err == nil {
				t.Errorf("Parse harus error untuk input %q", tc.src)
			}
		})
	}
}

func TestParseTopLevelNotMap(t *testing.T) {
	_, err := Parse([]byte("- a\n- b\n"))
	if err == nil {
		t.Fatal("top-level seq harus ditolak")
	}
	if !strings.Contains(err.Error(), "top-level") {
		t.Errorf("pesan error tidak informatif: %v", err)
	}
}
