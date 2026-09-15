// Package toolregistry memuat Tool Registry — tools/registry.yaml
// (ROADMAP v3.0 §36) — via internal/yamlmini, dan menyediakan resolusi
// fail-closed nama tool dan capability.
//
// Tool Registry menentukan (§36): identitas tool, versi, image, digest,
// signature, risk, capability mapping, network requirement, approval
// requirement, dan evidence parser. Risk/approval spesifik per tool ada DI
// SINI — bukan di capability registry (§12); contoh: endpoint_discovery
// lewat nmap mewajibkan approval "always".
//
// Prinsip fail-closed (§35): entry invalid (field wajib hilang, enum salah,
// digest salah format, field tidak dikenal, duplikat) atau tool tidak
// dikenal SELALU error — tidak ada fallback diam-diam. Tool = untrusted
// dependency; capability = trusted interface.
package toolregistry

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"hermes-security-skills/internal/yamlmini"
)

// AllowedCapabilities: capability yang boleh dipetakan ke tool — harus
// terdaftar di capabilities/registry.yaml (ROADMAP §12). Disalin sebagai
// enum agar loader bisa menolak mapping ke capability tak dikenal tanpa
// siklus dependensi ke package capability.
var AllowedCapabilities = map[string]bool{
	"inspect_request":           true,
	"request_replay":            true,
	"request_mutation":          true,
	"response_comparison":       true,
	"endpoint_discovery":        true,
	"template_based_validation": true,
	"openapi_analysis":          true,
	"json_diff":                 true,
}

// AllowedRisks / AllowedApprovalRequirements: enum fail-closed (§36).
var AllowedRisks = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

var AllowedApprovalRequirements = map[string]bool{
	"automatic":   true, // boleh jalan tanpa scoped approval
	"conditional": true, // wajib scoped approval aktif
	"always":      true, // TIDAK PERNAH jalan tanpa scoped approval
}

// validName: nama tool kebab-case (nuclei, tool-nuclei).
var validName = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// validDigest: pin digest image (§40) — "sha256:" + 64 hex.
var validDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// validImageRef: nama image OCI sederhana (hermes-tool-nuclei) — tanpa
// spasi/karakter aneh; tag/digest dilarang digabung di sini (field sendiri).
var validImageRef = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)

// Tool satu entri registry (ROADMAP §36).
type Tool struct {
	Name                string // key entry, mis. nuclei
	Category            string // mis. port-scanning
	Image               string // mis. hermes-tool-nmap
	Version             string // versi tool ter-pin, mis. 7.93
	Digest              string // sha256:... (pin §40); "-" = belum di-pin CI
	SignatureRequired   bool   // verifikasi signature wajib (§40)
	Risk                string // low | medium | high | critical
	Provider            string // docker (image terkurasi §38)
	Capability          string // salah satu dari AllowedCapabilities
	NetworkRequirement  string // mis. third-party-passive-sources
	ApprovalRequirement string // automatic | conditional | always
	EvidenceParser      string // mis. validation-result-json (§33/§39)
	TemplatesVersion    string // opsional (mis. nuclei templates v10.4.8, §41)
	WordlistsVersion    string // opsional (mis. SecLists 2026.1)
}

// Ref mengembalikan image reference yang dipakai docker run: name@digest
// bila digest ter-pin (§40), else name:version (mode source/dev).
func (t Tool) Ref() string {
	d := strings.TrimSpace(t.Digest)
	if d != "" && d != "-" {
		return t.Image + "@" + d
	}
	return t.Image + ":" + t.Version
}

// Registry kumpulan tool berdasarkan nama.
type Registry struct {
	tools map[string]Tool
}

// Load membaca dan mem-parse tools/registry.yaml. Fail-closed: file tidak
// ada, tidak parseable, atau entry invalid = error.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("toolregistry: baca registry %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("toolregistry: parse registry %s: %w", path, err)
	}
	return FromMap(doc)
}

// FromMap membangun Registry dari dokumen yang sudah di-parse.
func FromMap(doc map[string]any) (*Registry, error) {
	raw, ok := doc["tools"]
	if !ok {
		return nil, fmt.Errorf("toolregistry: field 'tools' tidak ada")
	}
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("toolregistry: 'tools' harus map tidak kosong")
	}
	tools := make(map[string]Tool, len(m))
	for name, v := range m {
		tm, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("toolregistry: tool %q harus mapping", name)
		}
		t, err := parseTool(name, tm)
		if err != nil {
			return nil, err
		}
		if _, dup := tools[t.Name]; dup {
			return nil, fmt.Errorf("toolregistry: tool name duplikat %q", t.Name)
		}
		tools[t.Name] = t
	}
	return &Registry{tools: tools}, nil
}

// parseTool memvalidasi satu entry tool — fail-closed terhadap field wajib
// hilang, enum salah, format digest salah, dan field tidak dikenal
// (supply-chain registry: apa pun yang tidak bisa divalidasi = error,
// §35/§36).
func parseTool(key string, m map[string]any) (Tool, error) {
	// Field tidak dikenal ditolak — entry registry tidak boleh membawa
	// metadata tak terverifikasi.
	known := map[string]bool{
		"name": true, "category": true, "image": true, "version": true,
		"digest": true, "signature_required": true, "risk": true,
		"provider": true, "capability": true, "network_requirement": true,
		"approval_requirement": true, "evidence_parser": true,
		"templates_version": true, "wordlists_version": true,
	}
	for k := range m {
		if !known[k] {
			return Tool{}, fmt.Errorf("toolregistry: tool %q: field tidak dikenal %q (fail-closed)", key, k)
		}
	}

	t := Tool{Name: key}
	var err error
	if t.Name, err = requireString(key, m, "name"); err != nil {
		return Tool{}, err
	}
	if t.Name != key {
		return Tool{}, fmt.Errorf("toolregistry: tool %q: field name %q harus sama dengan key entry", key, t.Name)
	}
	if !validName.MatchString(t.Name) {
		return Tool{}, fmt.Errorf("toolregistry: tool name %q tidak valid (kebab-case)", t.Name)
	}
	if t.Category, err = requireString(key, m, "category"); err != nil {
		return Tool{}, err
	}
	if t.Image, err = requireString(key, m, "image"); err != nil {
		return Tool{}, err
	}
	if !validImageRef.MatchString(t.Image) {
		return Tool{}, fmt.Errorf("toolregistry: tool %q: image %q tidak valid", key, t.Image)
	}
	if t.Version, err = requireString(key, m, "version"); err != nil {
		return Tool{}, err
	}
	if t.Digest, err = optionalString(key, m, "digest"); err != nil {
		return Tool{}, err
	}
	if d := t.Digest; d != "" && d != "-" && !validDigest.MatchString(d) {
		return Tool{}, fmt.Errorf("toolregistry: tool %q: digest harus 'sha256:<64 hex>' atau '-' (didapat %q)", key, d)
	}
	sr, ok := m["signature_required"]
	if !ok {
		return Tool{}, fmt.Errorf("toolregistry: tool %q.signature_required wajib ada", key)
	}
	b, ok := sr.(bool)
	if !ok {
		// Fail-closed: tipe salah (mis. string "true") ditolak, bukan dikonversi.
		return Tool{}, fmt.Errorf("toolregistry: tool %q.signature_required harus bool", key)
	}
	t.SignatureRequired = b
	if t.Risk, err = requireString(key, m, "risk"); err != nil {
		return Tool{}, err
	}
	if !AllowedRisks[t.Risk] {
		return Tool{}, fmt.Errorf("toolregistry: tool %q: risk %q tidak dikenal (low|medium|high|critical)", key, t.Risk)
	}
	if t.Provider, err = requireString(key, m, "provider"); err != nil {
		return Tool{}, err
	}
	if t.Capability, err = requireString(key, m, "capability"); err != nil {
		return Tool{}, err
	}
	if !AllowedCapabilities[t.Capability] {
		return Tool{}, fmt.Errorf("toolregistry: tool %q: capability %q tidak terdaftar di capability registry (§12)", key, t.Capability)
	}
	if t.NetworkRequirement, err = requireString(key, m, "network_requirement"); err != nil {
		return Tool{}, err
	}
	if t.ApprovalRequirement, err = requireString(key, m, "approval_requirement"); err != nil {
		return Tool{}, err
	}
	if !AllowedApprovalRequirements[t.ApprovalRequirement] {
		return Tool{}, fmt.Errorf("toolregistry: tool %q: approval_requirement %q tidak dikenal (automatic|conditional|always)", key, t.ApprovalRequirement)
	}
	if t.EvidenceParser, err = requireString(key, m, "evidence_parser"); err != nil {
		return Tool{}, err
	}
	if t.TemplatesVersion, err = optionalString(key, m, "templates_version"); err != nil {
		return Tool{}, err
	}
	if t.WordlistsVersion, err = optionalString(key, m, "wordlists_version"); err != nil {
		return Tool{}, err
	}
	return t, nil
}

// Resolve mengambil tool berdasarkan nama — fail-closed jika tidak
// terdaftar (§35: tool tidak dikenal = error, bukan silent skip).
func (r *Registry) Resolve(name string) (Tool, error) {
	t, ok := r.tools[name]
	if !ok {
		return Tool{}, fmt.Errorf("toolregistry: tool %q tidak terdaftar (fail-closed, §36)", name)
	}
	return t, nil
}

// ResolveByCapability mengembalikan semua tool yang melayani sebuah
// capability, terurut by nama (deterministik). Capability tidak dikenal =
// error; tidak ada tool = error (fail-closed: capability provider "tool"
// tanpa tool terdaftar tidak boleh diam-diam kosong).
func (r *Registry) ResolveByCapability(capability string) ([]Tool, error) {
	if !AllowedCapabilities[capability] {
		return nil, fmt.Errorf("toolregistry: capability %q tidak terdaftar (§12)", capability)
	}
	out := make([]Tool, 0)
	for _, t := range r.tools {
		if t.Capability == capability {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		return nil, fmt.Errorf("toolregistry: tidak ada tool terdaftar untuk capability %q (fail-closed, §36)", capability)
	}
	return out, nil
}

// List mengembalikan semua tool terurut by nama (deterministik).
func (r *Registry) List() []Tool {
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Tool, 0, len(names))
	for _, n := range names {
		out = append(out, r.tools[n])
	}
	return out
}

// Count jumlah tool terdaftar.
func (r *Registry) Count() int { return len(r.tools) }

func requireString(tool string, m map[string]any, field string) (string, error) {
	v, ok := m[field]
	if !ok {
		return "", fmt.Errorf("toolregistry: tool %q.%s wajib ada", tool, field)
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("toolregistry: tool %q.%s harus string tidak kosong", tool, field)
	}
	return strings.TrimSpace(s), nil
}

func optionalString(tool string, m map[string]any, field string) (string, error) {
	v, present := m[field]
	if !present || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("toolregistry: tool %q.%s harus string", tool, field)
	}
	return strings.TrimSpace(s), nil
}
