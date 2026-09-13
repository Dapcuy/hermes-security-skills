package credential

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Format vault file (binary, kecil dan sengaja sederhana):
//
//	offset 0   : magic 8 byte "HMSGVL01"
//	offset 8   : version 1 byte (0x01)
//	offset 9   : salt 16 byte (acak per vault, tetap seumur vault)
//	offset 25  : ciphertext = nonce 12 byte || AES-256-GCM(JSON entries)
//
// Key = PBKDF2-HMAC-SHA256(passphrase, salt, kdfIterations). Salt di header
// membuat passphrase berbeda menghasilkan key berbeda; nonce acak disimpan
// di depan ciphertext per penulisan.
const (
	vaultMagic    = "HMSGVL01"
	vaultVersion  = 0x01
	saltSize      = 16
	nonceSize     = 12
	kdfIterations = 210000 // PBKDF2-HMAC-SHA256 (OWASP 2022 minimum; vault lokal kecil)
	headerSize    = len(vaultMagic) + 1 + saltSize
)

// minKdfIterations adalah batas bawah KERAS jumlah iterasi PBKDF2 yang boleh
// dipakai mendekripsi/menulis vault. Format file saat ini TIDAK menyimpan
// iteration count (hardcoded kdfIterations), jadi file craft tidak bisa
// memaksa iterasi rendah — batas ini memastikan itu tetap benar bila format
// nanti berkembang, dan menolak konfigurasi/param future yang lemah
// (fail-closed, lihat TestAdversarialVaultPBKDF2MinimumIterations).
const minKdfIterations = 100000

// ErrExpired, ErrNotFound, ErrPassphrase: error yang wajib dibedakan caller
// (fail-closed — jangan pernah menyamaratakan jadi satu).
var (
	ErrExpired    = errors.New("credential: kredensial sudah kadaluarsa")
	ErrNotFound   = errors.New("credential: account tidak ditemukan")
	ErrPassphrase = errors.New("credential: passphrase salah atau vault rusak/korup")
)

// validAccountID: charset aman untuk account reference (mencegah karakter
// aneh pada ID yang dipakai lintas sistem sebagai reference).
var validAccountID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@:-]{0,63}$`)

// Entry satu kredensial dalam vault. Secret TIDAK PERNAH boleh dicatat
// ke audit/log/reasoning (ROADMAP 23).
type Entry struct {
	AccountID string    `json:"account_id"`
	Purpose   string    `json:"purpose"`
	Secret    string    `json:"secret"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// EntryInfo metadata untuk List — TANPA secret.
type EntryInfo struct {
	AccountID string    `json:"account_id"`
	Purpose   string    `json:"purpose"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Expired   bool      `json:"expired"`
}

// Vault credential store terenkripsi satu file.
type Vault struct {
	path string
	salt []byte
	key  []byte
}

// Open membuka vault pada path. File belum ada = vault baru dibuat dengan
// salt acak (dipersist segera). File ada = passphrase diverifikasi dengan
// mendekripsi isi; gagal buka GCM = ErrPassphrase (fail-closed, TIDAK
// menimpa vault).
func Open(path, passphrase string) (*Vault, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, fmt.Errorf("credential: passphrase kosong (tolak — fail-closed)")
	}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return openExisting(path, data, passphrase)
	case errors.Is(err, os.ErrNotExist):
		return createVault(path, passphrase)
	default:
		return nil, fmt.Errorf("credential: baca vault %s: %w", path, err)
	}
}

// createVault membuat vault baru: salt acak, key derived, header + entries
// kosong dipersist segera agar file yang valid selalu ada di disk.
func createVault(path, passphrase string) (*Vault, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("credential: generate salt: %w", err)
	}
	key, err := kdfKey(passphrase, salt, kdfIterations)
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, salt: salt, key: key}
	if err := v.persist(map[string]Entry{}); err != nil {
		return nil, err
	}
	return v, nil
}

// openExisting mem-parse header, derive key dari salt header, verifikasi
// passphrase dengan membuka ciphertext (auth GCM).
func openExisting(path string, data []byte, passphrase string) (*Vault, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("%w: file terlalu pendek / header tidak valid", ErrPassphrase)
	}
	if string(data[:len(vaultMagic)]) != vaultMagic {
		return nil, fmt.Errorf("%w: magic tidak dikenal (bukan vault hermes)", ErrPassphrase)
	}
	if data[len(vaultMagic)] != vaultVersion {
		return nil, fmt.Errorf("%w: versi vault %d tidak didukung", ErrPassphrase, data[len(vaultMagic)])
	}
	salt := data[len(vaultMagic)+1 : headerSize]
	key, err := kdfKey(passphrase, salt, kdfIterations)
	if err != nil {
		return nil, err
	}
	if _, err := decryptEntries(key, data[headerSize:]); err != nil {
		return nil, err // sudah dibungkus ErrPassphrase
	}
	return &Vault{path: path, salt: append([]byte(nil), salt...), key: key}, nil
}

// newGCM membangun cipher AES-256-GCM dari key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("credential: init aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credential: init gcm: %w", err)
	}
	return gcm, nil
}

// decryptEntries membuka ciphertext GCM dan unmarshal entries.
// Auth failure (passphrase salah / ciphertext diubah / vault korup)
// = ErrPassphrase. TAMBER-EVIDENT: modifikasi satu byte pun gagal dibuka.
func decryptEntries(key, ciphertext []byte) (map[string]Entry, error) {
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("%w: ciphertext terlalu pendek", ErrPassphrase)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPassphrase, err)
	}
	var entries map[string]Entry
	if err := json.Unmarshal(plain, &entries); err != nil {
		return nil, fmt.Errorf("%w: isi vault tidak valid: %v", ErrPassphrase, err)
	}
	return entries, nil
}

// persist menulis ulang seluruh vault: header (magic+version+salt yang
// SAMA) || nonce acak || GCM(JSON entries). Atomik: temp + rename.
func (v *Vault) persist(entries map[string]Entry) error {
	plain, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("credential: marshal entries: %w", err)
	}
	gcm, err := newGCM(v.key)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("credential: generate nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)

	data := make([]byte, 0, headerSize+nonceSize+len(sealed))
	data = append(data, vaultMagic...)
	data = append(data, vaultVersion)
	data = append(data, v.salt...)
	data = append(data, nonce...)
	data = append(data, sealed...)

	if dir := filepath.Dir(v.path); dir != "" && dir != "." {
		// Folder credentials/ 0o700 — tidak boleh world-readable (§23).
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("credential: buat direktori %s: %w", dir, err)
		}
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("credential: tulis %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, v.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("credential: rename vault: %w", err)
	}
	return nil
}

// loadEntries membuka dan mendekripsi isi vault saat ini. Header file
// diverifikasi penuh (magic + VERSI + salt) terhadap handle yang hidup:
// tanpa ini, byte versi/salt di disk bisa di-tamper tanpa terdeteksi karena
// key sudah ada di memori (integritas header = tamper-evident, §25).
func (v *Vault) loadEntries() (map[string]Entry, error) {
	data, err := os.ReadFile(v.path)
	if err != nil {
		return nil, fmt.Errorf("credential: baca vault %s: %w", v.path, err)
	}
	if len(data) < headerSize || string(data[:len(vaultMagic)]) != vaultMagic {
		return nil, fmt.Errorf("%w: header vault tidak valid", ErrPassphrase)
	}
	if data[len(vaultMagic)] != vaultVersion {
		return nil, fmt.Errorf("%w: versi vault %d tidak didukung", ErrPassphrase, data[len(vaultMagic)])
	}
	if !bytes.Equal(data[len(vaultMagic)+1:headerSize], v.salt) {
		// Salt file berubah sejak Open — file bukan lagi vault yang sama
		// (atau ditimpa vault lain). Jangan coba-dekripsi: fail-closed.
		return nil, fmt.Errorf("%w: salt vault berubah — file bukan vault yang dibuka", ErrPassphrase)
	}
	return decryptEntries(v.key, data[headerSize:])
}

// Add menyimpan kredensial baru. Fail-closed: account sudah ada = error
// (rotasi = Remove lalu Add, meninggalkan jejak eksplisit), expires di
// masa lalu = error, field kosong = error.
func (v *Vault) Add(accountID, purpose, secret string, expiresAt time.Time) error {
	if !validAccountID.MatchString(accountID) {
		return fmt.Errorf("credential: account id %q tidak valid (huruf/angka/_.@:- , maks 64)", accountID)
	}
	if strings.TrimSpace(purpose) == "" {
		return fmt.Errorf("credential: purpose wajib diisi")
	}
	if secret == "" {
		return fmt.Errorf("credential: secret kosong (tolak — fail-closed)")
	}
	if expiresAt.IsZero() {
		return fmt.Errorf("credential: expires_at wajib diisi")
	}
	if !time.Now().Before(expiresAt) {
		return fmt.Errorf("credential: expires_at %s sudah lewat — tolak (fail-closed)", expiresAt.Format(time.RFC3339))
	}
	entries, err := v.loadEntries()
	if err != nil {
		return err
	}
	if _, exists := entries[accountID]; exists {
		return fmt.Errorf("credential: account %q sudah ada (rotasi = remove lalu add)", accountID)
	}
	entries[accountID] = Entry{
		AccountID: accountID,
		Purpose:   purpose,
		Secret:    secret,
		ExpiresAt: expiresAt.UTC(),
		CreatedAt: time.Now().UTC(),
	}
	return v.persist(entries)
}

// Get mengambil kredensial utuh. Kredensial kadaluarsa TIDAK pernah
// dikembalikan (fail-closed, §23: expired authorization = credential
// tidak lagi bisa dipakai).
func (v *Vault) Get(accountID string) (Entry, error) {
	entries, err := v.loadEntries()
	if err != nil {
		return Entry{}, err
	}
	e, ok := entries[accountID]
	if !ok {
		return Entry{}, fmt.Errorf("%w: %q", ErrNotFound, accountID)
	}
	if !time.Now().Before(e.ExpiresAt) {
		return Entry{}, fmt.Errorf("%w: %q (expired %s)", ErrExpired, accountID, e.ExpiresAt.Format(time.RFC3339))
	}
	return e, nil
}

// List mengembalikan metadata SEMUA kredensial TANPA secret (urut account).
func (v *Vault) List() ([]EntryInfo, error) {
	entries, err := v.loadEntries()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]EntryInfo, 0, len(ids))
	for _, id := range ids {
		e := entries[id]
		out = append(out, EntryInfo{
			AccountID: e.AccountID,
			Purpose:   e.Purpose,
			ExpiresAt: e.ExpiresAt,
			CreatedAt: e.CreatedAt,
			Expired:   !now.Before(e.ExpiresAt),
		})
	}
	return out, nil
}

// Remove menghapus kredensial. Tidak ada = error (eksplisit, bukan no-op).
func (v *Vault) Remove(accountID string) error {
	entries, err := v.loadEntries()
	if err != nil {
		return err
	}
	if _, ok := entries[accountID]; !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, accountID)
	}
	delete(entries, accountID)
	return v.persist(entries)
}

// Path lokasi file vault.
func (v *Vault) Path() string { return v.path }
