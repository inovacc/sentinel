package transport

import (
	"net"
	"testing"
)

// stubAddr lets us drive remoteIP without a real connection.
type stubAddr struct{ s string }

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return a.s }

func TestRemoteIPParsesHostPort(t *testing.T) {
	if got := remoteIP(stubAddr{"203.0.113.4:51000"}); got != "203.0.113.4" {
		t.Fatalf("remoteIP = %q, want 203.0.113.4", got)
	}
	// A bare address (no port) falls back to the raw string.
	if got := remoteIP(stubAddr{"203.0.113.5"}); got != "203.0.113.5" {
		t.Fatalf("remoteIP fallback = %q", got)
	}
}

func TestRemoteIPHandlesTCPAddr(t *testing.T) {
	a := &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 7399}
	if got := remoteIP(a); got != "198.51.100.2" {
		t.Fatalf("remoteIP(TCPAddr) = %q", got)
	}
}
