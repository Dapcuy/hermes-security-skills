package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture manifest inline (mirror struktur runtimes/proxy/manifests/
// image-manifest.yaml — kolom digest "-" mode source).
const manifestFixture = `# komentar harus diabaikan
registry: ghcr.io/<owner>

images:
  - name: hermes-validator-http
    tag: 0.1.0
    dockerfile: runtimes/docker/images/http-validator/Dockerfile
    base: gcr.io/distroless/static-debian12:nonroot
    network: none
    egress: false
    digest: "-"

  - name: hermes-validator-json
    tag: 0.1.0
    dockerfile: runtimes/docker/images/json-validator/Dockerfile
    base: gcr.io/distroless/static-debian12:nonroot
    network: none
    egress: false
    digest: "-"

  - name: hermes-validator-pinned
    tag: 0.1.0
    base: gcr.io/distroless/static-debian12:nonroot
    egress: false
    digest: sha256:abc123def
`

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image-manifest.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadManifest(t *testing.T) {
	m, err := Load(writeFixture(t, manifestFixture))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if m.Registry != "ghcr.io/<owner>" {
		t.Errorf("registry = %q", m.Registry)
	}
	if len(m.Images) != 3 {
		t.Fatalf("images = %d, mau 3", len(m.Images))
	}
	http := m.Images[0]
	if http.Name != "hermes-validator-http" || http.Tag != "0.1.0" {
		t.Errorf("entry pertama salah: %+v", http)
	}
	if http.Egress {
		t.Error("validator egress harus false")
	}
	if http.Network != "none" {
		t.Errorf("network = %q", http.Network)
	}
}

func TestRefTagVsDigest(t *testing.T) {
	m, err := Load(writeFixture(t, manifestFixture))
	if err != nil {
		t.Fatal(err)
	}
	// digest "-" → fallback name:tag.
	if got := m.Images[0].Ref(); got != "hermes-validator-http:0.1.0" {
		t.Errorf("ref = %q, mau name:tag", got)
	}
	// digest terisi → pinned name@digest (§14).
	if got := m.Images[2].Ref(); got != "hermes-validator-pinned@sha256:abc123def" {
		t.Errorf("ref = %q, mau name@digest", got)
	}
}

func TestResolve(t *testing.T) {
	m, err := Load(writeFixture(t, manifestFixture))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"http-response-comparison": "hermes-validator-http:0.1.0", // alias §21
		"header-analysis":          "hermes-validator-http:0.1.0",
		"json-diff":                "hermes-validator-json:0.1.0",
		"hermes-validator-http":    "hermes-validator-http:0.1.0", // lookup nama langsung
	}
	for id, want := range cases {
		got, err := m.Resolve(id)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", id, err)
			continue
		}
		if got != want {
			t.Errorf("Resolve(%q) = %q, mau %q", id, got, want)
		}
	}
	// Fail-closed: tidak dikenal / kosong.
	if _, err := m.Resolve("validator-asing"); err == nil {
		t.Error("validator tidak dikenal harus error")
	}
	if _, err := m.Resolve(""); err == nil {
		t.Error("validator kosong harus error")
	}
	if _, err := m.Resolve("  "); err == nil {
		t.Error("validator whitespace harus error")
	}
}

func TestResolveQualifiesRegistry(t *testing.T) {
	content := strings.Replace(manifestFixture, "ghcr.io/<owner>", "ghcr.io/acme", 1)
	m, err := Load(writeFixture(t, content))
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Resolve("http-response-comparison")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ghcr.io/acme/hermes-validator-http:0.1.0" {
		t.Fatalf("qualified ref = %q", got)
	}
}

func TestLoadManifestFailClosed(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"tanpa images", "registry: x\n"},
		{"images kosong", "images: []\n"},
		{"image tanpa name", "images:\n  - tag: 0.1.0\n    digest: '-'\n"},
		{"image tanpa tag", "images:\n  - name: hermes-x\n    digest: '-'\n"},
		{"digest aneh", "images:\n  - name: hermes-x\n    tag: 0.1.0\n    digest: not-a-digest\n"},
		{"name duplikat", "images:\n  - name: a\n    tag: 0.1.0\n    digest: '-'\n  - name: a\n    tag: 0.2.0\n    digest: '-'\n"},
		{"entry bukan mapping", "images:\n  - hanya_string\n"},
		{"egress bukan bool", "images:\n  - name: a\n    tag: 0.1.0\n    egress: mungkin\n"},
		{"yaml rusak", "\ta: ["},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeFixture(t, tc.yaml)); err == nil {
				t.Errorf("harus error (fail-closed)")
			}
		})
	}
	// File hilang.
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("file hilang harus error")
	}
}

func TestOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image-overrides.yaml")
	content := "# build lokal dev\nhttp-response-comparison: hermes/validator-http:dev\nhermes-validator-json: hermes/validator-json:dev\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	ov, err := LoadOverrides(path)
	if err != nil {
		t.Fatalf("LoadOverrides error: %v", err)
	}
	if len(ov) != 2 {
		t.Fatalf("overrides = %d, mau 2", len(ov))
	}
	if ref, ok := ApplyOverride(ov, "http-response-comparison"); !ok || ref != "hermes/validator-http:dev" {
		t.Errorf("ApplyOverride = %q, %v", ref, ok)
	}
	if _, ok := ApplyOverride(ov, "tidak-ada"); ok {
		t.Error("override tidak ada harus false")
	}
	if _, ok := ApplyOverride(nil, "x"); ok {
		t.Error("overrides nil harus false")
	}

	// Fail-closed.
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("key_tanpa_nilai:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverrides(bad); err == nil {
		t.Error("override nilai null harus error")
	}
	spaces := filepath.Join(t.TempDir(), "spaces.yaml")
	if err := os.WriteFile(spaces, []byte("k: ref dengan spasi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverrides(spaces); err == nil {
		t.Error("ref berspasi harus error")
	}
	if _, err := LoadOverrides(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("file hilang harus error")
	}
}

// Mirror penuh manifest asli project: Load harus sukses dan semua validator
// yang dipakai control plane resolve-able (guard terhadap drift manifest).
func TestRealManifestResolves(t *testing.T) {
	const real = "../../runtimes/proxy/manifests/image-manifest.yaml"
	if _, err := os.Stat(real); err != nil {
		t.Skipf("manifest asli tidak ditemukan dari CWD test: %v", err)
	}
	m, err := Load(real)
	if err != nil {
		t.Fatalf("manifest asli gagal di-load: %v", err)
	}
	for _, id := range []string{"http-response-comparison", "json-diff", "openapi-analysis"} {
		ref, err := m.Resolve(id)
		if err != nil {
			t.Errorf("Resolve(%s): %v", id, err)
		}
		if !strings.Contains(ref, "hermes-validator") {
			t.Errorf("Resolve(%s) = %q", id, ref)
		}
	}
}
