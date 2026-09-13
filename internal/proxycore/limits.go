package proxycore

import (
	"sync"
	"time"
)

// Budget adalah counter max_requests global (§8, §22): setiap eksekusi request
// outbound mengambil satu slot. Habis = semua eksekusi berikutnya ditolak
// (fail-closed, HTTP 429 di level API).
type Budget struct {
	mu        sync.Mutex
	remaining int
}

// NewBudget membuat budget dengan jumlah slot awal.
func NewBudget(maxRequests int) *Budget {
	return &Budget{remaining: maxRequests}
}

// Take mengambil satu slot; false berarti budget habis.
func (b *Budget) Take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

// Remaining mengembalikan jumlah slot tersisa (untuk logging/diagnostik).
func (b *Budget) Remaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.remaining
}

// TokenBucket adalah rate limiter sederhana (token bucket, §22):
// kapasitas burst = rate (rps), refill linear rps token/detik.
// Allow() = false berarti request DITOLAK (fail-closed), tidak pernah menunggu.
type TokenBucket struct {
	mu     sync.Mutex
	rate   float64   // token per detik
	burst  float64   // kapasitas
	tokens float64   // token tersedia
	last   time.Time // waktu refill terakhir
}

// NewTokenBucket membuat bucket dengan rps token/detik dan burst = rps.
func NewTokenBucket(rps int) *TokenBucket {
	r := float64(rps)
	if r < 1 {
		r = 1
	}
	return &TokenBucket{
		rate:   r,
		burst:  r,
		tokens: r, // mulai penuh (burst)
		last:   time.Now(),
	}
}

// Allow mencoba mengambil satu token tanpa menunggu.
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.last).Seconds()
	if elapsed > 0 {
		tb.tokens += elapsed * tb.rate
		if tb.tokens > tb.burst {
			tb.tokens = tb.burst
		}
		tb.last = now
	}
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}
