package events

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Cache index.jsonl (opsional, hanya optimasi performa): baris pertama adalah
// meta berisi fingerprint direktori; baris berikutnya adalah Entry satu per
// baris. Bila fingerprint saat load tidak cocok, cache diabaikan dan index
// dibangun ulang dari file.
//
// Adversarial (§25): fingerprint WAJIB berbasis hash KONTEN file (bukan hanya
// nama+ukuran+mtime). Attacker yang mengubah isi evidence lalu memulihkan
// mtime/ukuran file tidak boleh mendapat index basi dari cache — hash konten
// berubah, fingerprint berubah, index di-rebuild, dan parseAndVerify menolak
// evidence tamper (fail-closed).
const (
	cacheFileName = "index.jsonl"
	cacheVersion  = 2
)

type fileMeta struct {
	name string
	size int64
	hash string // sha256 hex dari KONTEN file (bukan metadata)
}

type cacheMeta struct {
	Cache          string `json:"cache"`
	Version        int    `json:"version"`
	DirFingerprint string `json:"dir_fingerprint"`
}

// fingerprint hash deterministik atas daftar file (nama:ukuran:hash-konten).
func fingerprint(files []fileMeta) string {
	var b strings.Builder
	for _, f := range files {
		b.WriteString(f.name)
		b.WriteByte(':')
		b.WriteString(strconv.FormatInt(f.size, 10))
		b.WriteByte(':')
		b.WriteString(f.hash)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// readCache mencoba memuat index dari cache; ok=false berarti cache absen,
// korup, atau fingerprint tidak cocok → rebuild dari file.
func readCache(dir, wantFingerprint string) ([]Entry, bool) {
	data, err := os.ReadFile(filepath.Join(dir, cacheFileName))
	if err != nil {
		return nil, false
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 1 {
		return nil, false
	}
	var meta cacheMeta
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil {
		return nil, false
	}
	if meta.Cache != "events-index" || meta.Version != cacheVersion || meta.DirFingerprint != wantFingerprint {
		return nil, false
	}
	entries := make([]Entry, 0, len(lines)-1)
	for _, ln := range lines[1:] {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			return nil, false // cache korup → rebuild
		}
		entries = append(entries, e)
	}
	return entries, true
}

// writeCache menulis cache index (best-effort; dipanggil setelah scan sukses).
// Kegagalan tulis (mis. dir read-only) diabaikan oleh caller.
func writeCache(dir, dirFingerprint string, entries []Entry) error {
	var b strings.Builder
	meta, err := json.Marshal(cacheMeta{Cache: "events-index", Version: cacheVersion, DirFingerprint: dirFingerprint})
	if err != nil {
		return err
	}
	b.Write(meta)
	b.WriteByte('\n')
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("events: siapkan dir cache %s: %w", dir, err)
	}
	return os.WriteFile(filepath.Join(dir, cacheFileName), []byte(b.String()), 0o600)
}
