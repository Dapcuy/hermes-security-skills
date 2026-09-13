package credential

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestVault(t *testing.T, path, pass string) *Vault {
	t.Helper()
	v, err := Open(path, pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v
}

func TestVaultAddGetRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	v := openTestVault(t, path, "passphrase-kuat-123")
	exp := time.Now().Add(24 * time.Hour).UTC()
	if err := v.Add("account-a", "idor test akun A", "SUPERSECRET-VALUE-1", exp); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Roundtrip melalui proses "baru" (vault dibuka ulang dari disk).
	v2 := openTestVault(t, path, "passphrase-kuat-123")
	got, err := v2.Get("account-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Secret != "SUPERSECRET-VALUE-1" {
		t.Errorf("secret roundtrip salah: %q", got.Secret)
	}
	if got.Purpose != "idor test akun A" {
		t.Errorf("purpose salah: %q", got.Purpose)
	}
	if !got.ExpiresAt.Equal(exp) {
		t.Errorf("expires_at berubah: %v vs %v", got.ExpiresAt, exp)
	}
}

func TestVaultWrongPassphraseFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	v := openTestVault(t, path, "benar")
	if err := v.Add("acct", "purpose", "secret-value", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Passphrase salah = error; vault TIDAK boleh tertimpa/reset.
	if _, err := Open(path, "salah"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("Open passphrase salah = %v, mau ErrPassphrase", err)
	}
	vOK, err := Open(path, "benar")
	if err != nil {
		t.Fatalf("vault asli harus masih bisa dibuka: %v", err)
	}
	if e, err := vOK.Get("acct"); err != nil || e.Secret != "secret-value" {
		t.Errorf("isi vault berubah setelah percobaan passphrase salah: %v %v", e, err)
	}
	// Passphrase kosong ditolak keras.
	if _, err := Open(path, ""); err == nil {
		t.Error("passphrase kosong harus error")
	}
	if _, err := Open(path, "   "); err == nil {
		t.Error("passphrase whitespace harus error")
	}
}

func TestVaultExpiredFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	v := openTestVault(t, path, "pass")
	// Add dengan expiry masa lalu ditolak saat Add.
	if err := v.Add("old", "p", "s", time.Now().Add(-time.Minute)); err == nil {
		t.Error("Add dengan expires masa lalu harus error")
	}
	// Expiry yang lewat SETELAH add tetap ditolak saat Get.
	if err := v.Add("soon", "p", "s-soon", time.Now().Add(50*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := v.Get("soon"); !errors.Is(err, ErrExpired) {
		t.Fatalf("Get expired = %v, mau ErrExpired", err)
	}
	// List tetap menandai expired (metadata boleh terlihat, secret tidak).
	infos, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || !infos[0].Expired {
		t.Errorf("List harus menandai expired: %+v", infos)
	}
}

func TestVaultListNeverShowsSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	v := openTestVault(t, path, "pass")
	if err := v.Add("acct-x", "purpose-x", "TOP-SECRET-XYZ", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	infos, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("mau 1 entri, dapat %d", len(infos))
	}
	// Entri List adalah struct berbeda tanpa field secret — tapi jaga-jaga
	// cek representasi teksnya juga tidak pernah memuat secret.
	b, _ := json.Marshal(infos)
	if bytes.Contains(b, []byte("TOP-SECRET-XYZ")) {
		t.Error("KEBOCORAN: secret muncul di output List")
	}
	// File vault di disk tidak menyimpan plaintext.
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("TOP-SECRET-XYZ")) {
		t.Error("KEBOCORAN: secret plaintext ada di file vault")
	}
}

func TestVaultRemoveAndDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	v := openTestVault(t, path, "pass")
	exp := time.Now().Add(time.Hour)
	if err := v.Add("acct", "p", "s1", exp); err != nil {
		t.Fatal(err)
	}
	if err := v.Add("acct", "p", "s2", exp); err == nil {
		t.Error("duplicate account harus error")
	}
	if err := v.Remove("tidak-ada"); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove tidak ada = %v, mau ErrNotFound", err)
	}
	if err := v.Remove("acct"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := v.Get("acct"); !errors.Is(err, ErrNotFound) {
		t.Errorf("setelah remove harus ErrNotFound, dapat %v", err)
	}
	// Rotasi eksplisit: remove lalu add.
	if err := v.Add("acct", "p", "s2", exp); err != nil {
		t.Fatalf("add ulang setelah remove: %v", err)
	}
	got, _ := v.Get("acct")
	if got.Secret != "s2" {
		t.Errorf("rotasi gagal: %q", got.Secret)
	}
}

func TestVaultTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	v := openTestVault(t, path, "pass")
	if err := v.Add("acct", "p", "s", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Ubah satu byte ciphertext (flip bit terakhir) lalu tulis kembali.
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "pass"); !errors.Is(err, ErrPassphrase) {
		t.Errorf("vault diubah = %v, mau ErrPassphrase (fail-closed)", err)
	}
	// Magic asing ditolak.
	if err := os.WriteFile(path, []byte("BUKAN-VAULT-FILE-XYZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "pass"); err == nil {
		t.Error("file asing harus ditolak")
	}
}

func TestVaultAddFailClosedInputs(t *testing.T) {
	v := openTestVault(t, filepath.Join(t.TempDir(), "vault.enc"), "pass")
	exp := time.Now().Add(time.Hour)
	if err := v.Add("../evil", "p", "s", exp); err == nil {
		t.Error("account id path traversal harus ditolak")
	}
	if err := v.Add("", "p", "s", exp); err == nil {
		t.Error("account id kosong harus ditolak")
	}
	if err := v.Add("acct", " ", "s", exp); err == nil {
		t.Error("purpose kosong harus ditolak")
	}
	if err := v.Add("acct", "p", "", exp); err == nil {
		t.Error("secret kosong harus ditolak")
	}
	if err := v.Add("acct", "p", "s", time.Time{}); err == nil {
		t.Error("expires zero harus ditolak")
	}
}

func TestPBKDF2Vectors(t *testing.T) {
	// Vektor standar PBKDF2-HMAC-SHA256 (RFC 7914 test suite / dokumen publik).
	cases := []struct {
		pass, salt string
		iter, klen int
		want       string
	}{
		{"password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{"password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
			"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"},
	}
	for i, c := range cases {
		got := pbkdf2Key([]byte(c.pass), []byte(c.salt), c.iter, c.klen, sha256.New)
		if !strings.EqualFold(hex.EncodeToString(got), c.want) {
			t.Errorf("vektor %d: got %s want %s", i, hex.EncodeToString(got), c.want)
		}
	}
}
