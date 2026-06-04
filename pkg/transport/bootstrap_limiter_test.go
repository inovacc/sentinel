package transport

import (
	"testing"
	"time"
)

func TestPerIPLimiterConcurrentCap(t *testing.T) {
	l := newPerIPLimiter(2, 100) // 2 concurrent, rate effectively unlimited here
	rel1, ok1 := l.acquire("10.0.0.1")
	rel2, ok2 := l.acquire("10.0.0.1")
	if !ok1 || !ok2 {
		t.Fatal("first two acquisitions from one IP should succeed")
	}
	if _, ok3 := l.acquire("10.0.0.1"); ok3 {
		t.Fatal("third concurrent acquisition should be rejected")
	}
	// A different IP is unaffected.
	if _, ok := l.acquire("10.0.0.2"); !ok {
		t.Fatal("a second IP must not be throttled by the first")
	}
	// Releasing one frees a slot.
	rel1()
	if _, ok := l.acquire("10.0.0.1"); !ok {
		t.Fatal("releasing a slot should allow a new acquisition")
	}
	rel2()
}

func TestPerIPLimiterRateCap(t *testing.T) {
	l := newPerIPLimiter(100, 2) // generous concurrency, 2 new conns/sec
	// Burst of 2 succeeds, 3rd is rate-limited (then released so concurrency
	// is not the limiter).
	for i := 0; i < 2; i++ {
		rel, ok := l.acquire("10.0.0.9")
		if !ok {
			t.Fatalf("acquire %d should pass the rate gate", i)
		}
		rel()
	}
	if _, ok := l.acquire("10.0.0.9"); ok {
		t.Fatal("third acquisition within the same second should be rate-limited")
	}
}

func TestPerIPLimiterSweepEvictsIdle(t *testing.T) {
	l := newPerIPLimiter(2, 2)
	rel, _ := l.acquire("10.0.0.5")
	rel()
	l.sweep(time.Now().Add(time.Hour)) // pretend a lot of time passed
	if n := l.bucketCount(); n != 0 {
		t.Fatalf("idle bucket should be evicted, have %d", n)
	}
}
