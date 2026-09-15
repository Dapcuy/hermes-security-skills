// Package recovery provides offline, fail-closed backup/restore and retention primitives.
package recovery

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"hermes-security-skills/internal/audit"
)

type Source struct{ Name, Path string }
type Manifest struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	Files     []File `json:"files"`
}
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func digestBytes(data []byte) (int64, string) {
	sum := sha256.Sum256(data)
	return int64(len(data)), hex.EncodeToString(sum[:])
}

func safeArchiveName(name string) (string, error) {
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, `\\`) {
		return "", fmt.Errorf("recovery: invalid archive name %q", name)
	}
	clean := path.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("recovery: unsafe archive name %q", name)
	}
	return clean, nil
}

// CollectSources expands named files/directories into deterministic archive
// sources. The map key is the archive namespace and the value is a local path.
// Missing roots, symlinks, and non-regular files are rejected fail-closed.
func CollectSources(roots map[string]string) ([]Source, error) {
	if len(roots) == 0 {
		return nil, errors.New("recovery: at least one backup root is required")
	}
	keys := make([]string, 0, len(roots))
	for name := range roots {
		clean, err := safeArchiveName(name)
		if err != nil {
			return nil, err
		}
		if clean != name {
			return nil, fmt.Errorf("recovery: root name must be normalized: %q", name)
		}
		keys = append(keys, name)
	}
	sort.Strings(keys)
	// Root yang overlap akan menggandakan state dan membuat restore ambigu;
	// tolak sebelum membaca file apa pun.
	for i, left := range keys {
		leftAbs, err := filepath.Abs(roots[left])
		if err != nil {
			return nil, err
		}
		for _, right := range keys[i+1:] {
			rightAbs, err := filepath.Abs(roots[right])
			if err != nil {
				return nil, err
			}
			rel, err := filepath.Rel(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
			if err != nil {
				return nil, err
			}
			if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
				return nil, fmt.Errorf("recovery: backup roots overlap: %s and %s", left, right)
			}
			rel, err = filepath.Rel(filepath.Clean(rightAbs), filepath.Clean(leftAbs))
			if err != nil {
				return nil, err
			}
			if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
				return nil, fmt.Errorf("recovery: backup roots overlap: %s and %s", left, right)
			}
		}
	}
	var out []Source
	seen := map[string]bool{}
	for _, name := range keys {
		root := roots[name]
		info, err := os.Lstat(root)
		if err != nil {
			return nil, fmt.Errorf("recovery: backup root %s: %w", root, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("recovery: backup root %s is a symlink", root)
		}
		if info.Mode().IsRegular() {
			if seen[name] {
				return nil, fmt.Errorf("recovery: duplicate archive name %q", name)
			}
			seen[name] = true
			out = append(out, Source{Name: name, Path: root})
			continue
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("recovery: backup root %s is not a regular file or directory", root)
		}
		err = filepath.Walk(root, func(p string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if p == root {
				return nil
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("recovery: refusing symlink %s", p)
			}
			if fi.IsDir() {
				return nil
			}
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("recovery: non-regular file %s", p)
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			archiveName, err := safeArchiveName(path.Join(name, filepath.ToSlash(rel)))
			if err != nil {
				return err
			}
			if seen[archiveName] {
				return fmt.Errorf("recovery: duplicate archive name %q", archiveName)
			}
			seen[archiveName] = true
			out = append(out, Source{Name: archiveName, Path: p})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func Create(archivePath string, sources []Source) error {
	if archivePath == "" || len(sources) == 0 {
		return errors.New("recovery: archive path and sources are required")
	}
	files := make([]File, 0, len(sources))
	contents := make(map[string][]byte, len(sources))
	for _, s := range sources {
		name, err := safeArchiveName(s.Name)
		if err != nil || name != s.Name {
			return fmt.Errorf("recovery: invalid source name %q", s.Name)
		}
		if _, exists := contents[s.Name]; exists {
			return fmt.Errorf("recovery: duplicate source name %q", s.Name)
		}
		info, err := os.Lstat(s.Path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("recovery: source %s is not a regular file", s.Path)
		}
		data, err := os.ReadFile(s.Path)
		if err != nil {
			return err
		}
		n, sum := digestBytes(data)
		files = append(files, File{s.Name, n, sum})
		contents[s.Name] = data
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	m := Manifest{Version: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Files: files}
	mb, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(archivePath), ".backup-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) error {
		h := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err = write("manifest.json", mb); err != nil {
		tmp.Close()
		return err
	}
	for _, f := range files {
		if err = write(f.Name, contents[f.Name]); err != nil {
			tmp.Close()
			return err
		}
	}
	if err = tw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err = gz.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, archivePath)
}

func Verify(archivePath string) error { return inspect(archivePath, nil) }

func ArchiveSHA256(archivePath string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func VerifyDigest(archivePath, expected string) error {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if len(expected) != 64 {
		return errors.New("recovery: expected archive sha256 must be 64 lowercase hex characters")
	}
	for _, r := range expected {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return errors.New("recovery: expected archive sha256 must be 64 lowercase hex characters")
		}
	}
	actual, err := ArchiveSHA256(archivePath)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("recovery: archive sha256 mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func inspect(archivePath string, restoreDir *string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	gz, err := gzip.NewReader(br)
	if err != nil {
		return fmt.Errorf("recovery: invalid gzip: %w", err)
	}
	gz.Multistream(false)
	defer gz.Close()
	tr := tar.NewReader(gz)
	var m Manifest
	manifestSeen := false
	data := map[string][]byte{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if h.Name == "manifest.json" {
			if manifestSeen {
				return errors.New("recovery: duplicate manifest")
			}
			manifestSeen = true
		} else {
			name, nameErr := safeArchiveName(h.Name)
			if nameErr != nil || name != h.Name {
				return fmt.Errorf("recovery: unsafe archive path %q", h.Name)
			}
			if _, exists := data[h.Name]; exists {
				return fmt.Errorf("recovery: duplicate archive entry %q", h.Name)
			}
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return fmt.Errorf("recovery: unsupported archive entry type %q", h.Name)
		}
		b, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil {
			return e
		}
		if int64(len(b)) != h.Size {
			return errors.New("recovery: truncated archive entry")
		}
		if h.Name == "manifest.json" {
			if err = json.Unmarshal(b, &m); err != nil {
				return err
			}
		} else {
			data[h.Name] = b
		}
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return fmt.Errorf("recovery: gzip stream validation failed: %w", err)
	}
	if _, err := br.Peek(1); err != io.EOF {
		if err == nil {
			return errors.New("recovery: trailing bytes or additional gzip member")
		}
		return fmt.Errorf("recovery: trailing stream validation failed: %w", err)
	}
	if !manifestSeen {
		return errors.New("recovery: manifest.json is required")
	}
	if m.Version != 1 {
		return errors.New("recovery: unsupported manifest version")
	}
	manifestNames := map[string]bool{}
	for _, x := range m.Files {
		name, nameErr := safeArchiveName(x.Name)
		if nameErr != nil || name != x.Name || manifestNames[x.Name] {
			return fmt.Errorf("recovery: invalid or duplicate manifest file %q", x.Name)
		}
		manifestNames[x.Name] = true
		b, ok := data[x.Name]
		if !ok {
			return fmt.Errorf("recovery: missing %s", x.Name)
		}
		if int64(len(b)) != x.Size {
			return fmt.Errorf("recovery: size mismatch %s", x.Name)
		}
		_, sum := digestBytes(b)
		if sum != x.SHA256 {
			return fmt.Errorf("recovery: hash mismatch %s", x.Name)
		}
	}
	if len(manifestNames) != len(data) {
		return errors.New("recovery: archive contains files absent from manifest")
	}
	if restoreDir != nil {
		for n, b := range data {
			dst := filepath.Join(*restoreDir, filepath.FromSlash(n))
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(dst, b, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func Restore(archivePath, dir string) error {
	if dir == "" {
		return errors.New("recovery: restore dir required")
	}
	parent := filepath.Dir(filepath.Clean(dir))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := inspect(archivePath, &staging); err != nil {
		return err
	}
	if err := verifyRestoredAudits(staging); err != nil {
		return err
	}
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("recovery: restore destination already exists: %s", dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(staging, dir)
}

func verifyRestoredAudits(root string) error {
	var found bool
	err := filepath.Walk(root, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || info.Name() != "audit.jsonl" {
			return nil
		}
		found = true
		return audit.Verify(p)
	})
	if err != nil {
		return fmt.Errorf("recovery: audit verification failed: %w", err)
	}
	_ = found // backups without an audit file remain valid; callers may require one.
	return nil
}

type RetentionPolicy struct {
	MinAge       time.Duration
	AllowedNames []string
}

func ValidateCase(caseDir string, p RetentionPolicy, now time.Time) (files int, bytes int64, err error) {
	info, err := os.Stat(caseDir)
	if err != nil {
		return 0, 0, err
	}
	if !info.IsDir() {
		return 0, 0, errors.New("recovery: case path is not a directory")
	}
	if p.MinAge > 0 && now.Sub(info.ModTime()) < p.MinAge {
		return 0, 0, errors.New("recovery: case is younger than retention minimum")
	}
	allowed := map[string]bool{}
	for _, n := range p.AllowedNames {
		clean, err := safeArchiveName(n)
		if err != nil || clean != n || strings.Contains(n, "/") {
			return 0, 0, fmt.Errorf("recovery: invalid retention entry %q", n)
		}
		allowed[n] = true
	}
	entries, err := os.ReadDir(caseDir)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		if !allowed[e.Name()] {
			return 0, 0, fmt.Errorf("recovery: refusing cleanup of unallowlisted entry %q", e.Name())
		}
		if e.Type()&os.ModeSymlink != 0 {
			return 0, 0, fmt.Errorf("recovery: refusing cleanup of symlink %q", e.Name())
		}
		if e.IsDir() {
			if err := filepath.Walk(filepath.Join(caseDir, e.Name()), func(p string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if info.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("recovery: refusing cleanup of symlink %s", p)
				}
				if !info.IsDir() {
					files++
					bytes += info.Size()
				}
				return nil
			}); err != nil {
				return 0, 0, err
			}
		} else {
			entryInfo, infoErr := e.Info()
			if infoErr != nil {
				return 0, 0, infoErr
			}
			files++
			bytes += entryInfo.Size()
		}
	}
	return files, bytes, nil
}

func CleanupCase(caseDir string, p RetentionPolicy, now time.Time) error {
	if _, _, err := ValidateCase(caseDir, p, now); err != nil {
		return err
	}
	entries, err := os.ReadDir(caseDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(caseDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
