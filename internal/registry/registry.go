// Package registry: loader manifest image project (image-manifest.yaml,
// ROADMAP §13, §14, §21) dan resolusi validator ID → image ref.
//
// Sumber manifest: runtimes/proxy/manifests/image-manifest.yaml (satu file
// untuk semua image project). Kolom digest diisi "-" di source dan diganti
// CI saat publish (§14) — loader menerima keduanya:
//
//	digest "-" atau kosong → ref = name:tag   (mode source/dev)
//	digest sha256:...      → ref = name@digest (pinned, §14)
//
// Fail-closed: manifest tidak valid, image name kosong, atau validator
// tidak dikenal selalu error — tidak ada fallback diam-diam (§5.1).
package registry

import (
	"fmt"
	"os"
	"strings"

	"hermes-security-skills/internal/yamlmini"
)

// Image satu entri manifest.
type Image struct {
	Name        string // mis. hermes-validator-http (wajib)
	Tag         string // mis. 0.1.0 (wajib)
	Digest      string // "-" saat source; sha256:... saat publish (§14)
	Dockerfile  string
	Base        string
	Network     string
	Egress      bool
	Tool        string
	ToolVersion string
}

// Ref mengembalikan image reference yang dipakai docker:
// name@digest bila digest terisi (pinned, §14), else name:tag.
func (img Image) Ref() string {
	d := strings.TrimSpace(img.Digest)
	if d != "" && d != "-" {
		return img.Name + "@" + d
	}
	return img.Name + ":" + img.Tag
}

func (m *Manifest) ref(img Image) string {
	ref := img.Ref()
	reg := strings.TrimSuffix(strings.TrimSpace(m.Registry), "/")
	if reg == "" || strings.Contains(reg, "<owner>") {
		return ref
	}
	return reg + "/" + ref
}

// Manifest manifest image yang sudah divalidasi.
type Manifest struct {
	Registry string
	Images   []Image
	byName   map[string]int
}

// validatorImages memetakan validator ID (ROADMAP §21, field validator.id
// pada schemas/validation-task.schema.json) ke nama image di manifest.
// Image juga bisa di-resolve langsung dengan namanya (hermes-validator-http).
var validatorImages = map[string]string{
	"http-response-comparison": "hermes-validator-http",
	"header-analysis":          "hermes-validator-http",
	"openapi-analysis":         "hermes-validator-openapi",
	"json-diff":                "hermes-validator-json",
	"json-structure":           "hermes-validator-json",
	"python-validate":          "hermes-validator-python",
}

// Load membaca dan memvalidasi manifest image. Fail-closed.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: baca manifest %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("registry: parse manifest %s: %w", path, err)
	}
	m := &Manifest{byName: map[string]int{}}
	if reg, ok := doc["registry"]; ok {
		s, _ := reg.(string)
		m.Registry = s
	}
	raw, ok := doc["images"]
	if !ok {
		return nil, fmt.Errorf("registry: %s: field 'images' tidak ada", path)
	}
	seq, ok := raw.([]any)
	if !ok || len(seq) == 0 {
		return nil, fmt.Errorf("registry: %s: 'images' harus seq tidak kosong", path)
	}
	for i, item := range seq {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("registry: %s: images[%d] bukan mapping", path, i)
		}
		img, err := parseImage(entry, path, i)
		if err != nil {
			return nil, err
		}
		if _, dup := m.byName[img.Name]; dup {
			return nil, fmt.Errorf("registry: %s: image name duplikat %q", path, img.Name)
		}
		m.byName[img.Name] = len(m.Images)
		m.Images = append(m.Images, img)
	}
	return m, nil
}

func parseImage(entry map[string]any, path string, idx int) (Image, error) {
	str := func(key string) (string, error) {
		v, ok := entry[key]
		if !ok || v == nil {
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("registry: %s: images[%d].%s harus string", path, idx, key)
		}
		return strings.TrimSpace(s), nil
	}
	img := Image{}
	var err error
	if img.Name, err = str("name"); err != nil {
		return Image{}, err
	}
	if img.Tag, err = str("tag"); err != nil {
		return Image{}, err
	}
	if img.Digest, err = str("digest"); err != nil {
		return Image{}, err
	}
	if img.Dockerfile, err = str("dockerfile"); err != nil {
		return Image{}, err
	}
	if img.Base, err = str("base"); err != nil {
		return Image{}, err
	}
	if img.Network, err = str("network"); err != nil {
		return Image{}, err
	}
	if img.Tool, err = str("tool"); err != nil {
		return Image{}, err
	}
	if img.ToolVersion, err = str("tool_version"); err != nil {
		return Image{}, err
	}
	if v, ok := entry["egress"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return Image{}, fmt.Errorf("registry: %s: images[%d].egress harus bool", path, idx)
		}
		img.Egress = b
	}

	// Validasi fail-closed (deliverable: image name tidak boleh kosong).
	if img.Name == "" {
		return Image{}, fmt.Errorf("registry: %s: images[%d].name wajib ada", path, idx)
	}
	if img.Tag == "" && (img.Digest == "" || img.Digest == "-") {
		return Image{}, fmt.Errorf("registry: %s: images[%d].tag wajib ada saat digest belum di-pin", path, idx)
	}
	if d := img.Digest; d != "" && d != "-" && !strings.HasPrefix(d, "sha256:") {
		return Image{}, fmt.Errorf("registry: %s: images[%d].digest harus 'sha256:...' atau '-' (didapat %q)", path, idx, d)
	}
	return img, nil
}

// Resolve memetakan validator ID → image ref (name:tag atau name@digest).
// Validator ID bisa berupa ID validator (mis. "http-response-comparison",
// §21) atau langsung nama image di manifest. Tidak dikenal = error
// fail-closed (deliverable: image tidak dikenal = error).
func (m *Manifest) Resolve(validatorID string) (string, error) {
	id := strings.TrimSpace(validatorID)
	if id == "" {
		return "", fmt.Errorf("registry: validator ID kosong")
	}
	name := id
	if alias, ok := validatorImages[id]; ok {
		name = alias
	}
	idx, ok := m.byName[name]
	if !ok {
		return "", fmt.Errorf("registry: validator/image %q tidak dikenal di manifest (fail-closed, §21)", validatorID)
	}
	return m.ref(m.Images[idx]), nil
}

// ImageOf mengembalikan entri manifest untuk sebuah image name (audit).
func (m *Manifest) ImageOf(name string) (Image, bool) {
	idx, ok := m.byName[name]
	if !ok {
		return Image{}, false
	}
	return m.Images[idx], true
}

// ------------------------------------------------------------- Overrides

// LoadOverrides membaca file override image (opsional, untuk dev/lokal):
// YAML mapping "validator-id ATAU nama image" → image ref alternatif, mis:
//
//	# image-overrides.yaml — build lokal dev (§37 build-from-source path)
//	http-response-comparison: hermes/validator-http:dev
//
// Fail-closed: key/value harus string non-empty tanpa spasi.
func LoadOverrides(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: baca image-overrides %s: %w", path, err)
	}
	doc, err := yamlmini.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("registry: parse image-overrides %s: %w", path, err)
	}
	if len(doc) == 0 {
		return nil, fmt.Errorf("registry: %s: tidak ada override", path)
	}
	out := make(map[string]string, len(doc))
	for k, v := range doc {
		key := strings.TrimSpace(k)
		s, ok := v.(string)
		if key == "" || !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("registry: %s: override %q harus key->string image ref non-empty", path, k)
		}
		if strings.ContainsAny(s, " \t\n") {
			return nil, fmt.Errorf("registry: %s: image ref %q tidak valid (mengandung spasi)", path, s)
		}
		out[key] = strings.TrimSpace(s)
	}
	return out, nil
}

// ApplyOverride mengembalikan override untuk validatorID bila ada.
// Override tidak divalidasi terhadap manifest (memang untuk menimpanya,
// jalur build-from-source §37) — tapi tetap dicatat pemakainya di audit.
func ApplyOverride(overrides map[string]string, validatorID string) (string, bool) {
	if overrides == nil {
		return "", false
	}
	if ref, ok := overrides[validatorID]; ok && strings.TrimSpace(ref) != "" {
		return strings.TrimSpace(ref), true
	}
	return "", false
}
