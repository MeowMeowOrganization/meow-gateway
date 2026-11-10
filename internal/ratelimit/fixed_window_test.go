package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterWindowAndBoundedMemory(t *testing.T) {
	base := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	limiter := New(2, time.Minute, 1)
	limiter.now = func() time.Time { return base }
	for i := 0; i < 2; i++ {
		if ok, _ := limiter.Allow("a"); !ok {
			t.Fatal("rejected within quota")
		}
	}
	if ok, delay := limiter.Allow("a"); ok || delay != time.Minute {
		t.Fatalf("over-limit request: ok=%v retry=%v", ok, delay)
	}
	if ok, _ := limiter.Allow("b"); ok {
		t.Fatal("allowed unbounded new key")
	}
	base = base.Add(time.Minute)
	if ok, _ := limiter.Allow("b"); !ok {
		t.Fatal("expired bucket did not release capacity")
	}
}

func TestLimiterIsConcurrentAndExact(t *testing.T) {
	limiter := New(17, time.Hour, 10)
	var granted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := limiter.Allow("shared"); ok {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if granted.Load() != 17 {
		t.Fatalf("concurrent grants = %d, want 17", granted.Load())
	}
}
