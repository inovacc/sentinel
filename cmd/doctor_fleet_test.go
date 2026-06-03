package cmd

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/clierr"
)

func TestClassifyPeerProbe(t *testing.T) {
	caTrust := errors.New(`transport: authentication handshake failed: client: peer cert not signed by CA: x509: certificate signed by unknown authority`)
	expired := errors.New("x509: certificate has expired or is not yet valid")
	unreachable := errors.New("dial tcp 10.0.0.9:7400: connect: connection refused")

	tests := []struct {
		name string
		err  error
		want docStatus
	}{
		{"trust verified", nil, stOK},
		{"CA mismatch is a hard failure", caTrust, stFail},
		{"expired cert is a hard failure", expired, stFail},
		{"corrupt pinned CA is a hard failure", errInvalidPinnedCA, stFail},
		{"unreachable is only a warning", unreachable, stWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyPeerProbe("DEVID-1", tt.err)
			if got.status != tt.want {
				t.Fatalf("status = %s, want %s (detail=%q)", got.status, tt.want, got.detail)
			}
		})
	}
}

func TestSummarizeFleetTrust(t *testing.T) {
	t.Run("no peers is OK", func(t *testing.T) {
		if r := summarizeFleetTrust(nil); r.status != stOK {
			t.Errorf("status = %s, want OK", r.status)
		}
	})
	t.Run("all verified is OK", func(t *testing.T) {
		r := summarizeFleetTrust([]peerProbe{{"A", stOK, "ok"}, {"B", stOK, "ok"}})
		if r.status != stOK {
			t.Errorf("status = %s, want OK", r.status)
		}
	})
	t.Run("a warning dominates OK", func(t *testing.T) {
		r := summarizeFleetTrust([]peerProbe{{"A", stOK, "ok"}, {"B", stWarn, "unreachable"}})
		if r.status != stWarn {
			t.Errorf("status = %s, want WARN", r.status)
		}
	})
	t.Run("a failure dominates everything", func(t *testing.T) {
		r := summarizeFleetTrust([]peerProbe{{"A", stOK, "ok"}, {"B", stWarn, "x"}, {"C", stFail, "untrusted"}})
		if r.status != stFail {
			t.Errorf("status = %s, want FAIL", r.status)
		}
	})
}

// TestDialPeerTrust proves the probe catches the exact field failure: a peer
// whose served cert is not signed by the pinned CA.
func TestDialPeerTrust(t *testing.T) {
	caA, err := ca.Init(t.TempDir())
	if err != nil {
		t.Fatalf("init caA: %v", err)
	}
	srvCertPEM, srvKeyPEM, err := caA.SignDevice(ca.RoleOperator)
	if err != nil {
		t.Fatalf("sign server cert: %v", err)
	}
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = c.Close()
			}()
		}
	}()
	addr := ln.Addr().String()

	// Pinning the CA that actually signed the server cert: trust verifies.
	if err := dialPeerTrust(addr, caA.RootCertPEM(), nil, nil, 3*time.Second); err != nil {
		t.Fatalf("dialPeerTrust with correct pinned CA should succeed: %v", err)
	}

	// Pinning a different CA (the rotation scenario): trust must fail, and the
	// failure must be classifiable as a CA-trust problem.
	caB, err := ca.Init(t.TempDir())
	if err != nil {
		t.Fatalf("init caB: %v", err)
	}
	err = dialPeerTrust(addr, caB.RootCertPEM(), nil, nil, 3*time.Second)
	if err == nil {
		t.Fatal("dialPeerTrust with the wrong pinned CA should fail, got nil")
	}
	if d, ok := clierr.Classify(err); !ok || d.Kind != clierr.KindCATrust {
		t.Errorf("wrong-CA failure should classify as CA trust, got ok=%v err=%v", ok, err)
	}
}
