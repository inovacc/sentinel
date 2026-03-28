package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
)

func TestBootstrapFullHandshake(t *testing.T) {
	ts := newTestSetup(t)

	// --- Server (has CA) ---
	serverManager, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		CA:               ts.CA,
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		BootstrapTimeout: 10 * time.Second,
		Logger:           testLogger(),
		OnPeerAccepted: func(peerID string, peerCert []byte, role string) (bool, error) {
			return true, nil // Accept all peers in test.
		},
	})
	if err != nil {
		t.Fatalf("NewManager server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := serverManager.Start(ctx); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	defer serverManager.Stop()

	serverAddr := serverManager.BootstrapListener().Addr().String()

	// Start bootstrap server in background.
	bs := NewBootstrapServer(serverManager, "test-v1")
	go func() {
		_ = bs.Serve(ctx)
	}()

	// Give server a moment to start accepting.
	time.Sleep(100 * time.Millisecond)

	// --- Client (no CA, wants to join) ---
	clientManager, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		BootstrapCertPEM: ts.BootstrapCert2,
		BootstrapKeyPEM:  ts.BootstrapKey2,
		BootstrapTimeout: 10 * time.Second,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager client: %v", err)
	}

	bc := NewBootstrapClient(clientManager, "test-v1")
	result, err := bc.Connect(ctx, serverAddr, ca.RoleOperator)
	if err != nil {
		t.Fatalf("bootstrap Connect: %v", err)
	}

	// Verify result.
	if result.PeerDeviceID == "" {
		t.Error("expected non-empty peer device ID")
	}

	if len(result.SignedCertPEM) == 0 {
		t.Error("expected signed certificate")
	}

	if len(result.CACertPEM) == 0 {
		t.Error("expected CA certificate")
	}

	if result.MTLSAddr == "" {
		t.Error("expected mTLS address")
	}

	// Verify the signed cert is valid.
	_, err = ca.DeviceID(result.SignedCertPEM)
	if err != nil {
		t.Errorf("compute device ID from signed cert: %v", err)
	}

	// Verify server recorded the peer.
	peers := serverManager.TrustedPeers()
	if len(peers) != 1 {
		t.Errorf("expected 1 trusted peer on server, got %d", len(peers))
	}
}

func TestBootstrapPeerRejected(t *testing.T) {
	ts := newTestSetup(t)

	serverManager, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		CA:               ts.CA,
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		BootstrapTimeout: 10 * time.Second,
		Logger:           testLogger(),
		OnPeerAccepted: func(peerID string, peerCert []byte, role string) (bool, error) {
			return false, nil // Reject all peers.
		},
	})
	if err != nil {
		t.Fatalf("NewManager server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := serverManager.Start(ctx); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	defer serverManager.Stop()

	serverAddr := serverManager.BootstrapListener().Addr().String()

	bs := NewBootstrapServer(serverManager, "test-v1")
	go func() {
		_ = bs.Serve(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	clientManager, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		BootstrapCertPEM: ts.BootstrapCert2,
		BootstrapKeyPEM:  ts.BootstrapKey2,
		BootstrapTimeout: 10 * time.Second,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager client: %v", err)
	}

	bc := NewBootstrapClient(clientManager, "test-v1")
	_, err = bc.Connect(ctx, serverAddr, ca.RoleOperator)
	if err == nil {
		t.Fatal("expected error when peer is rejected")
	}
}

func TestGenerateBootstrapIdentity(t *testing.T) {
	cert, key, err := GenerateBootstrapIdentity()
	if err != nil {
		t.Fatalf("GenerateBootstrapIdentity: %v", err)
	}

	if len(cert) == 0 {
		t.Error("expected non-empty certificate")
	}
	if len(key) == 0 {
		t.Error("expected non-empty key")
	}

	// Should produce a valid device ID.
	id, err := ca.DeviceID(cert)
	if err != nil {
		t.Fatalf("DeviceID: %v", err)
	}
	if !ca.ValidateDeviceID(id) {
		t.Errorf("device ID validation failed: %s", id)
	}
}

func TestWireProtocol_RoundTrip(t *testing.T) {
	// Use net.Pipe which implements net.Conn.
	server, client := net.Pipe()
	defer func() {
		_ = server.Close()
		_ = client.Close()
	}()

	hello := HelloMessage{
		DeviceID: "TEST-DEVICE-ID",
		Hostname: "test-host",
		OS:       "linux",
		Arch:     "amd64",
		Version:  "v1.0.0",
		HasCA:    true,
	}

	go func() {
		if err := writeMessage(client, MsgHello, hello); err != nil {
			t.Errorf("writeMessage: %v", err)
		}
	}()

	env, err := readEnvelope(server)
	if err != nil {
		t.Fatalf("readEnvelope: %v", err)
	}

	if env.Type != MsgHello {
		t.Errorf("expected type %s, got %s", MsgHello, env.Type)
	}

	var decoded HelloMessage
	if err := env.DecodePayload(&decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}

	if decoded.DeviceID != hello.DeviceID {
		t.Errorf("device ID = %q, want %q", decoded.DeviceID, hello.DeviceID)
	}
	if decoded.Hostname != hello.Hostname {
		t.Errorf("hostname = %q, want %q", decoded.Hostname, hello.Hostname)
	}
}

func TestWireProtocol_ErrorMessage(t *testing.T) {
	server, client := net.Pipe()
	defer func() {
		_ = server.Close()
		_ = client.Close()
	}()

	go func() {
		_ = writeMessage(client, MsgError, ErrorMessage{
			Code:    "test_error",
			Message: "something went wrong",
		})
	}()

	_, err := readTypedMessage[HelloMessage](server, MsgHello)
	if err == nil {
		t.Fatal("expected error for MsgError")
	}
}
