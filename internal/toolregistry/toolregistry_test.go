package toolregistry

import (
	"strings"
	"testing"
)

// fixtureRegistry: registry inline lengkap (tanpa file) — 5 tool mengikuti
// tools/registry.yaml.
func fixtureRegistry(t *testing.T) *Registry {
	t.Helper()
	doc := map[string]any{
		"tools": map[string]any{
			"nuclei": map[string]any{
				"name": "nuclei", "category": "vulnerability-detection",
				"image": "hermes-tool-nuclei", "version": "3.3.9",
				"digest":             "sha256:af9c62369480cb6b2c825161231db5a3dfed449f44a96c273d13d8d045f9a373",
				"signature_required": true, "risk": "medium", "provider": "docker",
				"capability":          "template_based_validation",
				"network_requirement": "target-http", "approval_requirement": "conditional",
				"evidence_parser": "validation-result-json", "templates_version": "v10.4.8",
			},
			"subfinder": map[string]any{
				"name": "subfinder", "category": "attack-surface-discovery",
				"image": "hermes-tool-subfinder", "version": "2.16.0",
				"digest":             "-",
				"signature_required": true, "risk": "low", "provider": "docker",
				"capability":          "endpoint_discovery",
				"network_requirement": "third-party-passive-sources", "approval_requirement": "automatic",
				"evidence_parser": "validation-result-json",
			},
			"httpx": map[string]any{
				"name": "httpx", "category": "url-probing",
				"image": "hermes-tool-httpx", "version": "1.12.0",
				"digest":             "sha256:6e8e333d2ea9a91ae270f3d7a0bff4a86a653b7fab37b57270ea9526af1f19ae",
				"signature_required": true, "risk": "low", "provider": "docker",
				"capability":          "endpoint_discovery",
				"network_requirement": "target-http", "approval_requirement": "automatic",
				"evidence_parser": "validation-result-json",
			},
			"nmap": map[string]any{
				"name": "nmap", "category": "port-scanning",
				"image": "hermes-tool-nmap", "version": "7.93",
				"digest":             "sha256:6b9054dcea800cc5cbbece3bb4adccb2c14f048ea77557abdaf644021183ae4d",
				"signature_required": true, "risk": "high", "provider": "docker",
				"capability":          "endpoint_discovery",
				"network_requirement": "target-connect-scan", "approval_requirement": "always",
				"evidence_parser": "validation-result-json",
			},
			"ffuf": map[string]any{
				"name": "ffuf", "category": "content-discovery",
				"image": "hermes-tool-ffuf", "version": "2.3.0",
				"digest":             "sha256:637bb1aa7d92403abf182fb0be6edd433ac8eb7dfe4a1edd9691ef486b42d5cf",
				"signature_required": true, "risk": "medium", "provider": "docker",
				"capability":          "endpoint_discovery",
				"network_requirement": "target-http", "approval_requirement": "conditional",
				"evidence_parser": "validation-result-json", "wordlists_version": "SecLists 2026.1",
			},
		},
	}
	reg, err := FromMap(doc)
	if err != nil {
		t.Fatalf("FromMap fixture: %v", err)
	}
	return reg
}

func TestLoadFixtureAndResolve(t *testing.T) {
	reg := fixtureRegistry(t)
	if reg.Count() != 5 {
		t.Fatalf("mau 5 tool, dapat %d", reg.Count())
	}
	nmap, err := reg.Resolve("nmap")
	if err != nil {
		t.Fatalf("Resolve nmap: %v", err)
	}
	if nmap.Risk != "high" || nmap.ApprovalRequirement != "always" ||
		nmap.Capability != "endpoint_discovery" || !nmap.SignatureRequired {
		t.Errorf("entry nmap salah: %+v", nmap)
	}
	if nmap.Ref() != "hermes-tool-nmap@sha256:6b9054dcea800cc5cbbece3bb4adccb2c14f048ea77557abdaf644021183ae4d" {
		t.Errorf("Ref nmap (digest pin) salah: %s", nmap.Ref())
	}
	// Digest "-" (belum di-pin CI) -> ref name:version.
	sub, err := reg.Resolve("subfinder")
	if err != nil {
		t.Fatalf("Resolve subfinder: %v", err)
	}
	if sub.Ref() != "hermes-tool-subfinder:2.16.0" {
		t.Errorf("Ref subfinder (mode source) salah: %s", sub.Ref())
	}
	// Tool tidak dikenal = error fail-closed.
	if _, err := reg.Resolve("sqlmap"); err == nil {
		t.Error("tool tidak dikenal harus error (fail-closed)")
	}
}

func TestResolveByCapability(t *testing.T) {
	reg := fixtureRegistry(t)
	tools, err := reg.ResolveByCapability("endpoint_discovery")
	if err != nil {
		t.Fatalf("ResolveByCapability endpoint_discovery: %v", err)
	}
	// Terurut deterministik: ffuf, httpx, nmap, subfinder.
	var names []string
	for _, tl := range tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "ffuf,httpx,nmap,subfinder" {
		t.Errorf("urut salah: %v", names)
	}
	val, err := reg.ResolveByCapability("template_based_validation")
	if err != nil || len(val) != 1 || val[0].Name != "nuclei" {
		t.Fatalf("template_based_validation harus resolve nuclei: %v %v", val, err)
	}
	// Capability tidak dikenal = error.
	if _, err := reg.ResolveByCapability("sql_injection"); err == nil {
		t.Error("capability tidak dikenal harus error")
	}
	// Capability dikenal tapi tanpa tool = error fail-closed (tidak boleh kosong diam-diam).
	empty, err := FromMap(map[string]any{"tools": map[string]any{
		"nuclei": map[string]any{
			"name": "nuclei", "category": "vulnerability-detection",
			"image": "hermes-tool-nuclei", "version": "3.3.9",
			"digest":             "-",
			"signature_required": true, "risk": "medium", "provider": "docker",
			"capability":          "template_based_validation",
			"network_requirement": "target-http", "approval_requirement": "conditional",
			"evidence_parser": "validation-result-json",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := empty.ResolveByCapability("endpoint_discovery"); err == nil {
		t.Error("capability tanpa tool terdaftar harus error (fail-closed)")
	}
}

func TestFailClosedInvalidEntries(t *testing.T) {
	valid := map[string]any{
		"name": "nmap", "category": "port-scanning",
		"image": "hermes-tool-nmap", "version": "7.93",
		"digest":             "-",
		"signature_required": true, "risk": "high", "provider": "docker",
		"capability":          "endpoint_discovery",
		"network_requirement": "target-connect-scan", "approval_requirement": "always",
		"evidence_parser": "validation-result-json",
	}
	mk := func(mutate func(m map[string]any)) map[string]any {
		m := map[string]any{}
		for k, v := range valid {
			m[k] = v
		}
		if mutate != nil {
			mutate(m)
		}
		return map[string]any{"tools": map[string]any{"nmap": m}}
	}
	cases := []struct {
		label  string
		doc    map[string]any
		expect string
	}{
		{"risk enum salah", mk(func(m map[string]any) { m["risk"] = "extreme" }), "risk"},
		{"risk tipe salah", mk(func(m map[string]any) { m["risk"] = 2 }), "risk"},
		{"approval enum salah", mk(func(m map[string]any) { m["approval_requirement"] = "sometimes" }), "approval_requirement"},
		{"capability tidak dikenal", mk(func(m map[string]any) { m["capability"] = "nmap_scan" }), "capability"},
		{"digest format salah", mk(func(m map[string]any) { m["digest"] = "sha256:abc" }), "digest"},
		{"digest prefix salah", mk(func(m map[string]any) {
			m["digest"] = "md5:6b9054dcea800cc5cbbece3bb4adccb2c14f048ea77557abdaf644021183ae4d"
		}), "digest"},
		{"field wajib hilang", mk(func(m map[string]any) { delete(m, "evidence_parser") }), "wajib ada"},
		{"field tidak dikenal", mk(func(m map[string]any) { m["extra_flag"] = "bebas" }), "field tidak dikenal"},
		{"name tidak match key", mk(func(m map[string]any) { m["name"] = "nmapx" }), "sama dengan key"},
		{"signature_required tipe salah", mk(func(m map[string]any) { m["signature_required"] = "true" }), "signature_required"},
		{"image kosong", mk(func(m map[string]any) { m["image"] = "" }), "string tidak kosong"},
	}
	for _, tc := range cases {
		if _, err := FromMap(tc.doc); err == nil {
			t.Errorf("%s: harus error fail-closed", tc.label)
		} else if !strings.Contains(err.Error(), tc.expect) {
			t.Errorf("%s: error %q tidak menyebut %q", tc.label, err, tc.expect)
		}
	}
	// Structur registry rusak.
	if _, err := FromMap(map[string]any{}); err == nil {
		t.Error("tanpa field 'tools' harus error")
	}
	if _, err := FromMap(map[string]any{"tools": map[string]any{}}); err == nil {
		t.Error("'tools' kosong harus error")
	}
	if _, err := FromMap(map[string]any{"tools": "bukan-map"}); err == nil {
		t.Error("'tools' bukan map harus error")
	}
}

func TestListDeterministic(t *testing.T) {
	reg := fixtureRegistry(t)
	var names []string
	for _, tl := range reg.List() {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "ffuf,httpx,nmap,nuclei,subfinder" {
		t.Errorf("List tidak deterministik: %v", names)
	}
}
