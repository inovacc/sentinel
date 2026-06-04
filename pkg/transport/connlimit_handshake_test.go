package transport

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// wrapTLSForTest wraps base with a self-signed TLS listener that requires a
// client certificate. It reuses GenerateBootstrapIdentity from bootstrap.go so
// we don't duplicate cert generation logic. The helper is intentionally
// permissive about the CA pool (InsecureSkipVerify = false; we use
// tls.RequireAnyClientCert so the handshake will stall when the client sends
// nothing).
func wrapTLSForTest(t *testing.T, base net.Listener) net.Listener {
	t.Helper()
	certPEM, keyPEM, err := GenerateBootstrapIdentity()
	if err != nil {
		t.Fatalf("wrapTLSForTest: generate cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("wrapTLSForTest: load keypair: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// RequireAnyClientCert means the server asks for a client cert; a TCP
		// client that never sends a ClientHello will time out in the handshake.
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS13,
	}
	return tls.NewListener(base, cfg)
}

func TestHandshakeTimeoutDropsStalledClient(t *testing.T) {
	// A plain (non-TLS) listener wrapped so we can feed a TCP conn that never
	// sends a ClientHello. We exercise the deadline path via a real tls.Conn by
	// building a TLS server listener with a tiny handshake timeout.
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = base.Close() }()

	tlsLis := wrapTLSForTest(t, base) // helper builds a self-signed mTLS-style tls.Listener
	ll := newConnLimitListener(tlsLis, connLimitOpts{
		maxConns: 8, perDevice: 8, handshakeTimeout: 200 * time.Millisecond,
	}, NewLimitRecorderForTest())

	accepted := make(chan struct{}, 1)
	go func() {
		if c, aerr := ll.Accept(); aerr == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	// Connect at the TCP layer but never start the TLS handshake.
	raw, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()

	select {
	case <-accepted:
		t.Fatal("a stalled handshake should NOT be admitted")
	case <-time.After(600 * time.Millisecond):
		// Good: the wrapper timed out the handshake and dropped the conn.
	}
}
