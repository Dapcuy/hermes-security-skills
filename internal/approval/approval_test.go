package approval

import (
	"errors"
	"testing"
	"time"
)

func newTest(t *testing.T, max int, expires time.Time) *Approval {
	t.Helper()
	a, err := New("request_replay", "api.example.com", "GET", "/api/orders/123", max, "test-account-b", expires, "medium")
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	return a
}

func TestNewFailClosed(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	if _, err := New("", "h", "GET", "/", 1, "", expires, "low"); err == nil {
		t.Error("capability kosong harus error")
	}
	if _, err := New("c", "", "GET", "/", 1, "", expires, "low"); err == nil {
		t.Error("host kosong harus error")
	}
	if _, err := New("c", "h", "", "/", 1, "", expires, "low"); err == nil {
		t.Error("method kosong harus error")
	}
	if _, err := New("c", "h", "GET", "", 1, "", expires, "low"); err == nil {
		t.Error("path kosong harus error")
	}
	if _, err := New("c", "h", "GET", "/", 0, "", expires, "low"); err == nil {
		t.Error("max_requests 0 harus error")
	}
	if _, err := New("c", "h", "GET", "/", 1, "", time.Time{}, "low"); err == nil {
		t.Error("expires_at zero harus error")
	}
	if _, err := New("c", "h", "GET", "/", 1, "", expires, ""); err == nil {
		t.Error("risk kosong harus error")
	}
}

func TestExpiry(t *testing.T) {
	now := time.Now()
	a := newTest(t, 5, now.Add(10*time.Minute))
	if !a.IsValid(now) {
		t.Error("approval harus valid sebelum expiry")
	}
	later := now.Add(11 * time.Minute)
	if a.IsValid(later) {
		t.Error("approval harus invalid setelah expiry")
	}
	if err := a.ConsumeAt(later); !errors.Is(err, ErrExpired) {
		t.Errorf("ConsumeAt(setelah expiry) = %v, mau ErrExpired", err)
	}
	// Batas: pada persis waktu expiry juga invalid (now < expiresAt).
	if a.IsValid(now.Add(10 * time.Minute)) {
		t.Error("pada persis waktu expiry harus sudah invalid")
	}
}

func TestRevoke(t *testing.T) {
	now := time.Now()
	a := newTest(t, 5, now.Add(time.Hour))
	a.Revoke()
	if !a.Revoked() {
		t.Error("Revoked() = false setelah Revoke()")
	}
	if a.IsValid(now) {
		t.Error("approval yang dicabut harus invalid")
	}
	if err := a.ConsumeAt(now); !errors.Is(err, ErrRevoked) {
		t.Errorf("ConsumeAt setelah revoke = %v, mau ErrRevoked", err)
	}
	a.Revoke() // idempotent
	if !a.Revoked() {
		t.Error("Revoke() harus idempotent")
	}
}

func TestConsumeBudget(t *testing.T) {
	now := time.Now()
	a := newTest(t, 3, now.Add(time.Hour))
	for i := 0; i < 3; i++ {
		if err := a.ConsumeAt(now); err != nil {
			t.Fatalf("ConsumeAt ke-%d error: %v", i+1, err)
		}
		if got := a.Used(); got != i+1 {
			t.Errorf("Used() = %d, mau %d", got, i+1)
		}
		if got := a.Remaining(); got != 3-(i+1) {
			t.Errorf("Remaining() = %d, mau %d", got, 3-(i+1))
		}
	}
	// Budget habis -> tolak.
	if err := a.ConsumeAt(now); !errors.Is(err, ErrExhausted) {
		t.Errorf("ConsumeAt saat habis = %v, mau ErrExhausted", err)
	}
	// Budget tidak boleh berubah saat gagal.
	if got := a.Used(); got != 3 {
		t.Errorf("Used() = %d, mau tetap 3", got)
	}
	// Valid setelah habis = false.
	if a.IsValid(now) {
		t.Error("IsValid harus false saat budget habis")
	}
}

func TestConsumePrioritasError(t *testing.T) {
	now := time.Now()
	a := newTest(t, 1, now.Add(time.Hour))
	a.Revoke()
	// Revoked lebih dulu dari expired/exhausted.
	if err := a.ConsumeAt(now.Add(2 * time.Hour)); !errors.Is(err, ErrRevoked) {
		t.Errorf("ConsumeAt = %v, mau ErrRevoked", err)
	}
}
