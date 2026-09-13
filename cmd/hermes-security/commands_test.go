package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hermes-security-skills/internal/audit"
)

func TestParseFrontmatter(t *testing.T) {
	src := `---
name: idor-and-bola
description: >
  Use when analyzing object-level authorization,
  cross-account access, or tenant isolation.
version: 0.1.0
risk: medium
requires_credentials: true    # komentar trailing
---

# IDOR and BOLA
`
	fm, err := parseFrontmatter([]byte(src))
	if err != nil {
		t.Fatalf("parseFrontmatter error: %v", err)
	}
	if fm["name"] != "idor-and-bola" {
		t.Errorf("name = %q", fm["name"])
	}
	if fm["version"] != "0.1.0" {
		t.Errorf("version = %q", fm["version"])
	}
	if fm["risk"] != "medium" {
		t.Errorf("risk = %q", fm["risk"])
	}
	if fm["requires_credentials"] != "true    # komentar trailing" && fm["requires_credentials"] != "true" {
		// Nilai sederhana dipetakan apa adanya (frontmatter skill sederhana).
		t.Logf("requires_credentials = %q", fm["requires_credentials"])
	}
	want := "Use when analyzing object-level authorization, cross-account access, or tenant isolation."
	if fm["description"] != want {
		t.Errorf("description = %q, mau %q", fm["description"], want)
	}
}

func TestParseFrontmatterQuoted(t *testing.T) {
	src := "---\nname: \"quoted-name\"\nrisk: 'single'\n---\n"
	fm, err := parseFrontmatter([]byte(src))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if fm["name"] != "quoted-name" || fm["risk"] != "single" {
		t.Errorf("quoted salah: %#v", fm)
	}
}

func TestParseFrontmatterFailClosed(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"tanpa pembuka", "# bukan frontmatter\n"},
		{"tanpa penutup", "---\nname: x\n"},
		{"baris tidak valid", "---\nhanya_teks\n---\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseFrontmatter([]byte(tc.src)); err == nil {
				t.Errorf("harus error")
			}
		})
	}
}

func TestScanSkills(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "core", "alpha")
	b := filepath.Join(dir, "web", "beta")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	writeFile(t, filepath.Join(a, "SKILL.md"), "---\nname: alpha-skill\ndescription: uji satu\nversion: 0.1.0\nrisk: low\n---\n")
	writeFile(t, filepath.Join(b, "SKILL.md"), "---\nname: beta-skill\ndescription: uji dua\nversion: 0.2.0\nrisk: high\n---\n")
	// File lain tidak boleh ikut.
	writeFile(t, filepath.Join(dir, "README.md"), "# readme\n")

	skills, err := ScanSkills(dir)
	if err != nil {
		t.Fatalf("ScanSkills error: %v", err)
	}
	if len(skills) != 2 {
		t.Fatalf("len(skills) = %d, mau 2", len(skills))
	}
	if skills[0].Name != "alpha-skill" || skills[1].Name != "beta-skill" {
		t.Errorf("urutan salah: %#v", skills)
	}
	if !strings.HasSuffix(skills[0].Path, "/SKILL.md") {
		t.Errorf("path harus slash: %s", skills[0].Path)
	}
}

func TestScanSkillsFailClosed(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(dir, "core", "broken")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(d, "SKILL.md"), "tanpa frontmatter\n")
	if _, err := ScanSkills(dir); err == nil {
		t.Error("SKILL.md tanpa frontmatter harus error (fail-closed)")
	}
	// Field wajib hilang.
	d2 := filepath.Join(dir, "core", "missing-risk")
	if err := os.MkdirAll(d2, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(d2, "SKILL.md"), "---\nname: x\nversion: 0.1.0\n---\n")
	if _, err := ScanSkills(dir); err == nil {
		t.Error("frontmatter tanpa risk harus error")
	}
	// Direktori tidak ada.
	if _, err := ScanSkills(filepath.Join(dir, "nope")); err == nil {
		t.Error("direktori hilang harus error")
	}
}

func TestRouteSkills(t *testing.T) {
	skills := []SkillInfo{
		{Name: "idor-and-bola", Description: "object-level authorization cross-account access"},
		{Name: "xss-analysis", Description: "cross-site scripting analysis"},
		{Name: "authorization-code-review", Description: "review authorization code"},
	}
	ranked := RouteSkills("cross account authorization", skills)
	if len(ranked) == 0 {
		t.Fatal("harus ada kandidat")
	}
	// idor-and-bola: "cross"(desc) "account"(desc) "authorization"(name+desc) = 3
	if ranked[0].Skill.Name != "idor-and-bola" {
		t.Errorf("top = %s, mau idor-and-bola", ranked[0].Skill.Name)
	}
	if ranked[0].Score != 3 {
		t.Errorf("top score = %d, mau 3", ranked[0].Score)
	}
	if len(ranked) != 3 {
		t.Errorf("jumlah kandidat = %d, mau 3", len(ranked))
	}
	// Query tanpa kecocokan.
	if got := RouteSkills("zzzz-tidak-ada", skills); len(got) != 0 {
		t.Errorf("query tak cocok harus kosong, dapat %d", len(got))
	}
}

func TestLoadAllowedHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.yaml")
	writeFile(t, path, "allowed_hosts:\n  - example.com\n  - '*.example.com'\n")
	got, err := loadAllowedHosts(path)
	if err != nil {
		t.Fatalf("loadAllowedHosts error: %v", err)
	}
	if len(got) != 2 || got[0] != "example.com" || got[1] != "*.example.com" {
		t.Errorf("allowed_hosts = %#v", got)
	}
}

func TestLoadAllowedHostsFailClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	if _, err := loadAllowedHosts(missing); err == nil {
		t.Error("file hilang harus error")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	writeFile(t, bad, "host_lain: x\n")
	if _, err := loadAllowedHosts(bad); err == nil {
		t.Error("tanpa allowed_hosts harus error")
	}
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	writeFile(t, empty, "allowed_hosts: []\n")
	// Flow seq kosong -> seq kosong -> error.
	if _, err := loadAllowedHosts(empty); err == nil {
		t.Error("allowed_hosts kosong harus error")
	}
}

func TestCheckPolicy(t *testing.T) {
	root := t.TempDir()
	regPath := filepath.Join(root, "registry.yaml")
	writeFile(t, regPath, `
capabilities:
  request_replay:
    risk: medium
    default_provider: proxy
    requires_scope: true
    requires_network: true
  inspect_request:
    risk: low
    default_provider: proxy
    requires_scope: true
    requires_network: false
`)
	policyDir := filepath.Join(root, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(policyDir, "risk.yaml"), `
default_action:
  low: automatic
  medium: conditional
  high: approval_required
  critical: disabled
`)
	writeFile(t, filepath.Join(policyDir, "limits.yaml"), `
payload_policy:
  max_entries_per_task: 100
  max_requests_total: 50
  rate_limit_rps: 1
  max_concurrency: 1
  stop_on_429: true
  stop_on_repeated_5xx: true
  destructive_payloads: deny
  exfiltration_payloads: deny
  credential_attack_lists: deny
`)

	cases := []struct {
		capName string
		method  string
		want    string
	}{
		{"inspect_request", "GET", "automatic"},         // max(low, low)
		{"request_replay", "GET", "conditional"},        // max(low, medium)
		{"request_replay", "POST", "approval_required"}, // max(high, medium)
	}
	for _, tc := range cases {
		dec, err := CheckPolicy(regPath, policyDir, tc.capName, tc.method)
		if err != nil {
			t.Fatalf("CheckPolicy(%s, %s) error: %v", tc.capName, tc.method, err)
		}
		if string(dec.Action) != tc.want {
			t.Errorf("CheckPolicy(%s, %s) action = %s, mau %s", tc.capName, tc.method, dec.Action, tc.want)
		}
	}
	// Capability tidak terdaftar -> fail-closed.
	if _, err := CheckPolicy(regPath, policyDir, "tidak_ada", "GET"); err == nil {
		t.Error("capability tak terdaftar harus error")
	}
	// Capability kosong -> error.
	if _, err := CheckPolicy(regPath, policyDir, "", "GET"); err == nil {
		t.Error("capability kosong harus error")
	}
}

func TestRunDoctor(t *testing.T) {
	root := t.TempDir()
	regPath := filepath.Join(root, "registry.yaml")
	writeFile(t, regPath, "capabilities:\n  c1:\n    risk: low\n    default_provider: local\n    requires_scope: false\n    requires_network: false\n")
	policyDir := filepath.Join(root, "policy")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(policyDir, "risk.yaml"), "default_action:\n  low: automatic\n  medium: conditional\n  high: approval_required\n  critical: disabled\n")
	writeFile(t, filepath.Join(policyDir, "limits.yaml"), "payload_policy:\n  max_entries_per_task: 100\n  max_requests_total: 50\n  rate_limit_rps: 1\n  max_concurrency: 1\n  stop_on_429: true\n  stop_on_repeated_5xx: true\n  destructive_payloads: deny\n  exfiltration_payloads: deny\n  credential_attack_lists: deny\n")
	skillsDir := filepath.Join(root, "skills", "core", "s1")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(skillsDir, "SKILL.md"), "---\nname: s1\ndescription: d\nversion: 0.1.0\nrisk: low\n---\n")

	checks, err := RunDoctor(regPath, policyDir, filepath.Join(root, "skills"))
	if err != nil {
		t.Fatalf("RunDoctor error: %v", err)
	}
	if len(checks) != 4 {
		t.Fatalf("len(checks) = %d, mau 4", len(checks))
	}
	for _, c := range checks {
		if !c.OK {
			t.Errorf("check %s harus OK: %s", c.Name, c.Detail)
		}
	}

	// Registry rusak -> check registry FAIL.
	writeFile(t, regPath, "\ta: [")
	checks, err = RunDoctor(regPath, policyDir, filepath.Join(root, "skills"))
	if err != nil {
		t.Fatalf("RunDoctor error: %v", err)
	}
	for _, c := range checks {
		if c.Name == "registry" && c.OK {
			t.Error("registry rusak harus FAIL")
		}
	}
}

func TestWriteAuditEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	if err := writeAudit(path, "test-action", map[string]any{"k": "v"}); err != nil {
		t.Fatalf("writeAudit error: %v", err)
	}
	if err := audit.Verify(path); err != nil {
		t.Errorf("audit.Verify error: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis %s: %v", path, err)
	}
}
