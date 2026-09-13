// Package credential mengimplementasikan credential provider v0 (ROADMAP 23).
//
// Aturan arsitektural (§23):
//   - kredensial disimpan di store TERPISAH yang terenkripsi dan di-exclude
//     dari repo (default ./credentials/vault.enc — folder credentials/ ada
//     di .gitignore);
//   - skill/approval hanya merujuk REFERENCE (account id), bukan nilai;
//   - fail-closed: kredensial kadaluarsa tidak pernah dikembalikan,
//     passphrase salah = error (bukan fallback).
//
// Enkripsi: AES-256-GCM dengan key dari PBKDF2-HMAC-SHA256 (implementasi
// stdlib sendiri — project ini tanpa dependency eksternal). Salt acak
// disimpan di header vault file.
package credential

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

// pbkdf2Key menghasilkan key sepanjang keyLen byte dengan PBKDF2-HMAC
// (RFC 2898 / RFC 8018) memakai hash h. Implementasi mengikuti referensi
// x/crypto/pbkdf2 namun self-contained (stdlib only).
func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	if iter <= 0 || keyLen <= 0 {
		return nil
	}
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// U_1 = PRF(password, salt || INT_32_BE(block))
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Reset()
		prf.Write(salt)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1)); T = U_1 XOR ... XOR U_c
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

// kdfKey adalah wrapper kdf untuk vault (HMAC-SHA256, 32 byte).
func kdfKey(passphrase string, salt []byte, iterations int) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("credential: passphrase kosong")
	}
	if len(salt) < 8 {
		return nil, fmt.Errorf("credential: salt terlalu pendek")
	}
	key := pbkdf2Key([]byte(passphrase), salt, iterations, 32, sha256.New)
	if len(key) != 32 {
		return nil, fmt.Errorf("credential: derivasi key gagal")
	}
	return key, nil
}
