package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const registryFixture = `
version: 1

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

  json_diff:
    risk: low
    default_provider: local
    requires_scope: false
    requires_network: false
`

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis fixture: %v", err)
	}
	return path
}

func TestLoadAndResolve(t *testing.T) {
	path := writeFixture(t, registryFixture)
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if reg.Count() != 3 {
		t.Errorf("Count = %d, mau 3", reg.Count())
	}
	c, err := reg.Resolve("request_replay")
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if c.Risk != "medium" || c.DefaultProvider != "proxy" ||
		!c.RequiresScope || !c.RequiresNetwork || c.RequiresApproval != "conditional" {
		t.Errorf("capability tidak sesuai: %+v", c)
	}
	c, err = reg.Resolve("inspect_request")
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if c.RequiresApproval != "" {
		t.Errorf("requires_approval = %q, mau kosong (opsional)", c.RequiresApproval)
	}
}

func TestResolveFailClosed(t *testing.T) {
	reg, err := Load(writeFixture(t, registryFixture))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if _, err := reg.Resolve("tidak_ada"); err == nil {
		t.Error("Resolve capability tak terdaftar harus error")
	} else if !strings.Contains(err.Error(), "fail-closed") {
		t.Errorf("pesan error harus menyebut fail-closed: %v", err)
	}
}

func TestListSortedDeterministic(t *testing.T) {
	reg, err := Load(writeFixture(t, registryFixture))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	list := reg.List()
	if len(list) != 3 {
		t.Fatalf("len(List) = %d, mau 3", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Name >= list[i].Name {
			t.Errorf("List tidak terurut: %s lalu %s", list[i-1].Name, list[i].Name)
		}
	}
}

func TestLoadFailClosed(t *testing.T) {
	// File tidak ada.
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("Load file hilang harus error")
	}
	// YAML rusak.
	if _, err := Load(writeFixture(t, "a: 1\n\tb: [")); err == nil {
		t.Error("Load YAML rusak harus error")
	}
	// Field wajib hilang.
	missing := `
capabilities:
  broken_cap:
    risk: low
`
	if _, err := Load(writeFixture(t, missing)); err == nil {
		t.Error("field wajib hilang harus error")
	}
	// Tipe salah (requires_scope sebagai string, bukan bool).
	wrongType := `
capabilities:
  broken_cap:
    risk: low
    default_provider: proxy
    requires_scope: "true"
    requires_network: false
`
	if _, err := Load(writeFixture(t, wrongType)); err == nil {
		t.Error("requires_scope string harus ditolak (fail-closed)")
	}
	// Tanpa field capabilities.
	if _, err := Load(writeFixture(t, "version: 1\n")); err == nil {
		t.Error("tanpa 'capabilities' harus error")
	}
	// capabilities kosong (value null) harus error.
	empty := "capabilities:\n"
	if _, err := Load(writeFixture(t, empty)); err == nil {
		t.Error("capabilities kosong harus error")
	}
}
