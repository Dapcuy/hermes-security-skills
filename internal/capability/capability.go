// Package capability memuat capability registry dari
// capabilities/registry.yaml (via internal/yamlmini) dan menyediakan
// Resolve fail-closed (ROADMAP 5).
package capability

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"hermes-security-skills/internal/yamlmini"
)

// Capability satu entri registry.
type Capability struct {
	Name             string
	Risk             string // low | medium | high | critical
	DefaultProvider  string // proxy | local | docker | ...
	RequiresScope    bool
	RequiresNetwork  bool
	RequiresApproval string // "" (tidak ada), "conditional", dst.
}

// Registry kumpulan capability berdasarkan nama.
type Registry struct {
	caps map[string]Capability
}

// Load membaca dan mem-parse file registry. Fail-closed: file tidak ada,
// tidak parseable, atau field wajib hilang = error.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("capability: baca registry %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("capability: parse registry %s: %w", path, err)
	}
	return FromMap(doc)
}

// FromMap membangun Registry dari dokumen yang sudah di-parse.
func FromMap(doc map[string]any) (*Registry, error) {
	raw, ok := doc["capabilities"]
	if !ok {
		return nil, fmt.Errorf("capability: field 'capabilities' tidak ada")
	}
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("capability: 'capabilities' harus map tidak kosong")
	}
	caps := make(map[string]Capability, len(m))
	for name, v := range m {
		cm, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("capability: %q harus mapping", name)
		}
		c := Capability{Name: name}
		var err error
		if c.Risk, err = requireString(cm, name, "risk"); err != nil {
			return nil, err
		}
		if c.DefaultProvider, err = requireString(cm, name, "default_provider"); err != nil {
			return nil, err
		}
		if c.RequiresScope, err = requireBool(cm, name, "requires_scope"); err != nil {
			return nil, err
		}
		if c.RequiresNetwork, err = requireBool(cm, name, "requires_network"); err != nil {
			return nil, err
		}
		if rv, present := cm["requires_approval"]; present && rv != nil {
			s, ok := rv.(string)
			if !ok {
				return nil, fmt.Errorf("capability: %q.requires_approval harus string", name)
			}
			c.RequiresApproval = s
		}
		caps[name] = c
	}
	return &Registry{caps: caps}, nil
}

// Resolve mengambil capability berdasarkan nama — fail-closed jika
// tidak terdaftar.
func (r *Registry) Resolve(name string) (Capability, error) {
	c, ok := r.caps[name]
	if !ok {
		return Capability{}, fmt.Errorf("capability: %q tidak terdaftar (fail-closed)", name)
	}
	return c, nil
}

// List mengembalikan semua capability terurut by nama (deterministik).
func (r *Registry) List() []Capability {
	names := make([]string, 0, len(r.caps))
	for n := range r.caps {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Capability, 0, len(names))
	for _, n := range names {
		out = append(out, r.caps[n])
	}
	return out
}

// Count jumlah capability terdaftar.
func (r *Registry) Count() int { return len(r.caps) }

func requireString(m map[string]any, cap, field string) (string, error) {
	v, ok := m[field]
	if !ok {
		return "", fmt.Errorf("capability: %q.%s wajib ada", cap, field)
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("capability: %q.%s harus string tidak kosong", cap, field)
	}
	return s, nil
}

func requireBool(m map[string]any, cap, field string) (bool, error) {
	v, ok := m[field]
	if !ok {
		return false, fmt.Errorf("capability: %q.%s wajib ada", cap, field)
	}
	b, ok := v.(bool)
	if !ok {
		// Fail-closed: tipe salah (mis. string "true") ditolak, bukan dikonversi.
		return false, fmt.Errorf("capability: %q.%s harus bool", cap, field)
	}
	return b, nil
}
