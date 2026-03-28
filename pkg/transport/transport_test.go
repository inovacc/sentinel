package transport

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
)

// testSetup creates a CA and generates bootstrap + device identities for testing.
type testSetup struct {
	CA             *ca.CA
	BootstrapCert  []byte
	BootstrapKey   []byte
	DeviceCert     []byte
	DeviceKey      []byte
	BootstrapCert2 []byte
	BootstrapKey2  []byte
}

func newTestSetup(t *testing.T) *testSetup {
	t.Helper()
	dir := t.TempDir()

	authority, err := ca.Init(dir)
	if err != nil {
		t.Fatalf("init CA: %v", err)
	}

	// Generate bootstrap identities (self-signed).
	bootCert1, bootKey1, err := GenerateBootstrapIdentity()
	if err != nil {
		t.Fatalf("generate bootstrap identity 1: %v", err)
	}

	bootCert2, bootKey2, err := GenerateBootstrapIdentity()
	if err != nil {
		t.Fatalf("generate bootstrap identity 2: %v", err)
	}

	// Generate CA-signed device cert.
	devCert, devKey, err := authority.SignDevice(ca.RoleAdmin)
	if err != nil {
		t.Fatalf("sign device: %v", err)
	}

	return &testSetup{
		CA:             authority,
		BootstrapCert:  bootCert1,
		BootstrapKey:   bootKey1,
		DeviceCert:     devCert,
		DeviceKey:      devKey,
		BootstrapCert2: bootCert2,
		BootstrapKey2:  bootKey2,
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewManager_DetectsPhaseBootstrap(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    ":0",
		MTLSAddr:         ":0",
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if m.Phase() != PhaseBootstrap {
		t.Errorf("expected PhaseBootstrap, got %s", m.Phase())
	}

	if m.DeviceID() == "" {
		t.Error("expected non-empty device ID")
	}
}

func TestNewManager_DetectsPhaseMTLS(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    ":0",
		MTLSAddr:         ":0",
		CA:               ts.CA,
		DeviceCertPEM:    ts.DeviceCert,
		DeviceKeyPEM:     ts.DeviceKey,
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if m.Phase() != PhaseMTLS {
		t.Errorf("expected PhaseMTLS, got %s", m.Phase())
	}
}

func TestStartBootstrap_ListensAndCloses(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		BootstrapTimeout: 5 * time.Second,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	lis := m.BootstrapListener()
	if lis == nil {
		t.Fatal("expected bootstrap listener")
	}

	addr := lis.Addr().String()
	if addr == "" {
		t.Error("expected non-empty listener address")
	}

	m.Stop()

	if m.BootstrapListener() != nil {
		t.Error("expected nil bootstrap listener after stop")
	}
}

func TestStartMTLS_ListensAndCloses(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		CA:               ts.CA,
		DeviceCertPEM:    ts.DeviceCert,
		DeviceKeyPEM:     ts.DeviceKey,
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	lis := m.MTLSListener()
	if lis == nil {
		t.Fatal("expected mTLS listener")
	}

	// Bootstrap listener should NOT be open.
	if m.BootstrapListener() != nil {
		t.Error("expected nil bootstrap listener in mTLS phase")
	}

	m.Stop()
}

func TestTransitionToMTLS(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		CA:               ts.CA,
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		BootstrapTimeout: 10 * time.Second,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if m.Phase() != PhaseBootstrap {
		t.Fatalf("expected PhaseBootstrap, got %s", m.Phase())
	}

	// Transition to mTLS.
	if err := m.TransitionToMTLS(ctx, ts.DeviceCert, ts.DeviceKey); err != nil {
		t.Fatalf("TransitionToMTLS: %v", err)
	}

	if m.Phase() != PhaseMTLS {
		t.Errorf("expected PhaseMTLS, got %s", m.Phase())
	}

	if m.BootstrapListener() != nil {
		t.Error("expected bootstrap listener closed after transition")
	}

	if m.MTLSListener() == nil {
		t.Error("expected mTLS listener open after transition")
	}

	m.Stop()
}

func TestTransitionToMTLS_FailsFromMTLS(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		CA:               ts.CA,
		DeviceCertPEM:    ts.DeviceCert,
		DeviceKeyPEM:     ts.DeviceKey,
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx := context.Background()

	err = m.TransitionToMTLS(ctx, ts.DeviceCert, ts.DeviceKey)
	if err == nil {
		t.Error("expected error transitioning from mTLS phase")
	}
}

func TestEnableRenewal(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		CA:               ts.CA,
		DeviceCertPEM:    ts.DeviceCert,
		DeviceKeyPEM:     ts.DeviceKey,
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		BootstrapTimeout: 2 * time.Second,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Enable renewal (reopens bootstrap).
	if err := m.EnableRenewal(ctx); err != nil {
		t.Fatalf("EnableRenewal: %v", err)
	}

	if m.Phase() != PhaseRenewing {
		t.Errorf("expected PhaseRenewing, got %s", m.Phase())
	}

	if m.BootstrapListener() == nil {
		t.Error("expected bootstrap listener open during renewal")
	}

	// mTLS should still be running.
	if m.MTLSListener() == nil {
		t.Error("expected mTLS listener still open during renewal")
	}

	// Wait for renewal timeout.
	time.Sleep(3 * time.Second)

	if m.Phase() != PhaseMTLS {
		t.Errorf("expected PhaseMTLS after renewal timeout, got %s", m.Phase())
	}

	m.Stop()
}

func TestEnableRenewal_FailsFromBootstrap(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	err = m.EnableRenewal(context.Background())
	if err == nil {
		t.Error("expected error enabling renewal from bootstrap phase")
	}
}

func TestTrustedPeers(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    ":0",
		MTLSAddr:         ":0",
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	deviceID, _ := ca.DeviceID(ts.BootstrapCert2)
	m.AddTrustedPeer(deviceID, ts.BootstrapCert2)

	peers := m.TrustedPeers()
	if len(peers) != 1 {
		t.Errorf("expected 1 trusted peer, got %d", len(peers))
	}

	if _, ok := peers[deviceID]; !ok {
		t.Error("expected peer to be in trusted peers")
	}
}

func TestDeviceID_ChangesAfterTransition(t *testing.T) {
	ts := newTestSetup(t)

	m, err := NewManager(Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		CA:               ts.CA,
		BootstrapCertPEM: ts.BootstrapCert,
		BootstrapKeyPEM:  ts.BootstrapKey,
		BootstrapTimeout: 10 * time.Second,
		Logger:           testLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	bootstrapID := m.DeviceID()
	if bootstrapID == "" {
		t.Fatal("expected non-empty bootstrap device ID")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	if err := m.TransitionToMTLS(ctx, ts.DeviceCert, ts.DeviceKey); err != nil {
		t.Fatalf("TransitionToMTLS: %v", err)
	}

	mtlsID := m.DeviceID()
	if mtlsID == "" {
		t.Fatal("expected non-empty mTLS device ID")
	}

	// Device IDs should be different (different certs).
	if bootstrapID == mtlsID {
		t.Error("expected different device IDs for bootstrap and mTLS certs")
	}
}

func TestPhaseString(t *testing.T) {
	tests := []struct {
		phase Phase
		want  string
	}{
		{PhaseBootstrap, "bootstrap"},
		{PhaseMTLS, "mtls"},
		{PhaseRenewing, "renewing"},
		{Phase(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.phase.String(); got != tt.want {
			t.Errorf("Phase(%d).String() = %q, want %q", tt.phase, got, tt.want)
		}
	}
}
