package transport

import (
	"errors"
	"net"
	"testing"
	"time"
)

// fakeListener feeds a fixed set of connections then blocks until closed.
type fakeListener struct {
	conns chan net.Conn
	addr  net.Addr
}

func (f *fakeListener) Accept() (net.Conn, error) {
	c, ok := <-f.conns
	if !ok {
		return nil, errors.New("closed")
	}
	return c, nil
}
func (f *fakeListener) Close() error   { close(f.conns); return nil }
func (f *fakeListener) Addr() net.Addr { return f.addr }

func TestConnLimitGlobalCap(t *testing.T) {
	inner := &fakeListener{conns: make(chan net.Conn, 4), addr: &net.TCPAddr{}}
	rec := NewLimitRecorderForTest()
	ll := newConnLimitListener(inner, connLimitOpts{maxConns: 2, perDevice: 16, handshakeTimeout: time.Second}, rec)

	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	c3, s3 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close(); _ = c3.Close() }()
	inner.conns <- s1
	inner.conns <- s2
	inner.conns <- s3

	a1, err := ll.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}
	a2, err := ll.Accept()
	if err != nil {
		t.Fatalf("accept 2: %v", err)
	}
	// The 3rd connection is over the global cap: the wrapper closes s3 and keeps
	// accepting, so the next successful Accept must not return until a slot frees.
	freed := make(chan net.Conn, 1)
	go func() {
		a, aerr := ll.Accept()
		if aerr == nil {
			freed <- a
		}
	}()
	// s3 should be closed by the wrapper; reading from c3 returns an error.
	_ = c3.SetReadDeadline(time.Now().Add(time.Second))
	if _, rerr := c3.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("over-cap connection should have been closed")
	}
	// Free a slot; the pending Accept should complete.
	_ = a1.Close()
	select {
	case <-freed:
	case <-time.After(2 * time.Second):
		t.Fatal("freeing a slot did not unblock a pending Accept")
	}
	_ = a2.Close()
}
