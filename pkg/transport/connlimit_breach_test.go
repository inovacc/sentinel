package transport

import (
	"net"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/metrics"
)

// TestConnLimitGlobalCapEmitsConnCap proves that when the global MaxConns cap is
// saturated, Accept records a conn_cap breach (metric bump) before applying
// back-pressure. The breach is observed without dropping the connection.
func TestConnLimitGlobalCapEmitsConnCap(t *testing.T) {
	inner := &fakeListener{conns: make(chan net.Conn, 4), addr: &net.TCPAddr{}}
	rec := NewLimitRecorderForTest()
	ll := newConnLimitListener(inner, connLimitOpts{maxConns: 1, perDevice: 16, handshakeTimeout: time.Second}, rec)

	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	inner.conns <- s1
	inner.conns <- s2

	// First Accept fills the single global slot.
	a1, err := ll.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}

	before := metrics.LimitExceededTotalForTest()

	// Second Accept saturates the cap: it must record a conn_cap breach and then
	// block until a slot frees. Run it in a goroutine and free the slot.
	accepted := make(chan struct{}, 1)
	go func() {
		a2, aerr := ll.Accept()
		if aerr == nil {
			_ = a2.Close()
		}
		accepted <- struct{}{}
	}()

	// Give the goroutine time to hit the saturated branch and emit the breach.
	deadline := time.Now().Add(2 * time.Second)
	for metrics.LimitExceededTotalForTest() == before {
		if time.Now().After(deadline) {
			t.Fatal("saturated global cap did not emit a conn_cap breach")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := metrics.LimitExceededTotalForTest() - before; got != 1 {
		t.Fatalf("breach metric delta = %d, want 1", got)
	}

	// Free the slot so the pending Accept unblocks and the goroutine exits.
	_ = a1.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("freeing a slot did not unblock the pending Accept")
	}
}
