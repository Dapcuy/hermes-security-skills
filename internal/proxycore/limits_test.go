package proxycore

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBudget(t *testing.T) {
	b := NewBudget(2)
	if !b.Take() || !b.Take() {
		t.Fatal("dua Take pertama harus sukses")
	}
	if b.Take() {
		t.Error("Take ketiga harus gagal (budget habis)")
	}
	if b.Remaining() != 0 {
		t.Errorf("remaining = %d, mau 0", b.Remaining())
	}
}

func TestBudgetZero(t *testing.T) {
	b := NewBudget(0)
	if b.Take() {
		t.Error("budget 0 harus langsung menolak (fail-closed)")
	}
}

func TestTokenBucketDrainAndRefill(t *testing.T) {
	// Cepat: burst 100 di-drain, lalu deny; refill kecil diuji tanpa sleep lama.
	tb := NewTokenBucket(100)
	for i := 0; i < 100; i++ {
		if !tb.Allow() {
			t.Fatalf("Allow ke-%d harus sukses (burst penuh)", i+1)
		}
	}
	if tb.Allow() {
		t.Error("Allow setelah burst habis harus gagal")
	}
	// rps=100 -> 25ms memberi ~2.5 token; cukup untuk satu Allow tanpa sleep lama.
	time.Sleep(25 * time.Millisecond)
	if !tb.Allow() {
		t.Error("Allow setelah refill kecil harus sukses")
	}
}

func TestTokenBucketSingleBurst(t *testing.T) {
	tb := NewTokenBucket(1)
	if !tb.Allow() {
		t.Fatal("Allow pertama harus sukses (burst 1)")
	}
	if tb.Allow() {
		t.Error("Allow kedua tanpa jeda harus gagal (rps=1)")
	}
}

// TestAdversarialBudgetRaceDeterministic: 100 goroutine menembak Take() pada
// budget 10 SECARA BERSAMAAN — TEPAT 10 yang boleh sukses, deterministik
// (bukan sekadar bebas race detector): overdraw sebesar apa pun = bypass.
func TestAdversarialBudgetRaceDeterministic(t *testing.T) {
	b := NewBudget(10)
	const goroutines = 100
	var success atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // start bersamaan untuk memaksakan kontensi
			if b.Take() {
				success.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := success.Load(); got != 10 {
		t.Errorf("BYPASS: %d goroutine sukses Take pada budget 10, mau TEPAT 10", got)
	}
	if b.Remaining() != 0 {
		t.Errorf("Remaining = %d, mau 0", b.Remaining())
	}
}

// TestAdversarialBudgetExhaustedIsPermanent: budget habis tidak boleh bisa
// diisi ulang lewat jalur API mana pun.
func TestAdversarialBudgetExhaustedIsPermanent(t *testing.T) {
	b := NewBudget(1)
	if !b.Take() {
		t.Fatal("Take pertama harus sukses")
	}
	for i := 0; i < 100; i++ {
		if b.Take() {
			t.Fatalf("BYPASS: Take ke-%d sukses setelah budget habis", i+1)
		}
	}
}
