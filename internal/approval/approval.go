// Package approval mengimplementasikan scoped approval (ROADMAP 9).
//
// Approval tidak global: terikat pada capability, host, method, path,
// account reference, request budget, expiration, dan risk level.
// Revocation bersifat langsung; renewal harus lewat approval baru
// (tidak ada silent extension).
package approval

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrExpired   = errors.New("approval: sudah kadaluarsa")
	ErrRevoked   = errors.New("approval: sudah dicabut")
	ErrExhausted = errors.New("approval: request budget habis")
)

// Approval adalah satu otorisasi ter-scope. Jangan disalin by-value
// (mengandung mutex); gunakan *Approval.
type Approval struct {
	Capability  string    `json:"capability"`
	Host        string    `json:"host"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	MaxRequests int       `json:"max_requests"`
	AccountRef  string    `json:"account_ref,omitempty"` // credential reference, bukan nilai
	ExpiresAt   time.Time `json:"expires_at"`
	Risk        string    `json:"risk"`

	mu      sync.Mutex `json:"-"`
	used    int        `json:"-"`
	revoked bool       `json:"-"`
}

// New membangun Approval dengan validasi fail-closed terhadap field wajib.
func New(capability, host, method, path string, maxRequests int, accountRef string, expiresAt time.Time, risk string) (*Approval, error) {
	if capability == "" || host == "" || method == "" || path == "" {
		return nil, fmt.Errorf("approval: capability, host, method, dan path wajib diisi")
	}
	if maxRequests <= 0 {
		return nil, fmt.Errorf("approval: max_requests harus > 0")
	}
	if expiresAt.IsZero() {
		return nil, fmt.Errorf("approval: expires_at wajib diisi")
	}
	if risk == "" {
		return nil, fmt.Errorf("approval: risk wajib diisi")
	}
	return &Approval{
		Capability:  capability,
		Host:        host,
		Method:      method,
		Path:        path,
		MaxRequests: maxRequests,
		AccountRef:  accountRef,
		ExpiresAt:   expiresAt,
		Risk:        risk,
	}, nil
}

// IsValid melaporkan apakah approval masih berlaku pada waktu `now`:
// tidak dicabut, belum kadaluarsa, dan budget masih ada.
func (a *Approval) IsValid(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.validLocked(now)
}

func (a *Approval) validLocked(now time.Time) bool {
	if a.revoked {
		return false
	}
	if !now.Before(a.ExpiresAt) {
		return false
	}
	return a.used < a.MaxRequests
}

// Revoke mencabut approval kapan saja sebelum expiry. Idempotent.
// Setelah revoke, semua konsumsi berikutnya gagal.
func (a *Approval) Revoke() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revoked = true
}

// Revoked melaporkan status pencabutan.
func (a *Approval) Revoked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.revoked
}

// Consume memotong request budget satu unit (pakai waktu sekarang).
// Fail-closed: revoked/expired/habis = error dan budget tidak berubah.
func (a *Approval) Consume() error {
	return a.ConsumeAt(time.Now())
}

// ConsumeAt adalah Consume yang testable (waktu eksplisit).
func (a *Approval) ConsumeAt(now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.revoked {
		return ErrRevoked
	}
	if !now.Before(a.ExpiresAt) {
		return ErrExpired
	}
	if a.used >= a.MaxRequests {
		return ErrExhausted
	}
	a.used++
	return nil
}

// Used mengembalikan jumlah request yang sudah dikonsumsi.
func (a *Approval) Used() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.used
}

// Remaining mengembalikan sisa request budget.
func (a *Approval) Remaining() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.MaxRequests - a.used
}
