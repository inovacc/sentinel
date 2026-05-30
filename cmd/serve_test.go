package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/settings"
)

// TestMain points the daemon at a throwaway data dir and mints a CA + device
// identity once for the whole package. datadir.Root() is sync.Once-cached, so
// the env must be set before any datadir call — hence the shared setup here.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sentinel-cmd-test-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("SENTINEL_DATA_DIR", dir)
	_ = os.Setenv("SENTINEL_SKIP_PUBLIC_IP", "1") // avoid outbound HTTP during boot
	if err := setupTestIdentity(dir); err != nil {
		_ = os.RemoveAll(dir)
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// setupTestIdentity initializes a CA, signs an admin device cert, writes the
// device keypair, and saves a config that binds only ephemeral ports.
func setupTestIdentity(dir string) error {
	caDir, err := datadir.CADir()
	if err != nil {
		return err
	}
	authority, err := ca.Init(caDir)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := authority.SignDevice(ca.RoleAdmin)
	if err != nil {
		return err
	}
	certDir, err := datadir.CertDir()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "device.crt"), certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "device.key"), keyPEM, 0o600); err != nil {
		return err
	}

	cfg := settings.DefaultConfig()
	cfg.Listen.GRPC = "127.0.0.1:0"
	cfg.Listen.Bootstrap = "127.0.0.1:0"
	cfg.Listen.Metrics = "127.0.0.1:0"
	cfg.Sandbox.Root = filepath.Join(dir, "sandbox")
	cfg.Discovery.Enabled = false // avoid binding mDNS multicast in tests
	return settings.Save(datadir.ConfigPath(), cfg)
}

// TestBuildDaemon exercises the full wiring path (the part carrying the
// cognitive complexity) without binding ports or serving — the primary guard
// that the helper extraction preserved a working assembly.
func TestBuildDaemon(t *testing.T) {
	d, err := buildDaemon(t.Context())
	if err != nil {
		t.Fatalf("buildDaemon: %v", err)
	}
	defer d.cleanup()

	if d.logger == nil || d.grpcServer == nil || d.transportMgr == nil ||
		d.workerPool == nil || d.registry == nil || d.sessionMgr == nil {
		t.Fatal("buildDaemon returned a partially-wired daemon")
	}
	if d.deviceID == "" {
		t.Error("device ID was not derived from the device certificate")
	}
}

// TestRunDaemonCtxBootAndShutdown boots the full daemon on ephemeral ports and
// confirms a context cancel produces a clean shutdown (nil error).
func TestRunDaemonCtxBootAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	errc := make(chan error, 1)
	go func() { errc <- runDaemonCtx(ctx) }()

	// Fail fast if boot errors out; otherwise give it a moment to come up.
	select {
	case err := <-errc:
		cancel()
		t.Fatalf("daemon exited during startup: %v", err)
	case <-time.After(1 * time.Second):
	}

	cancel()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected clean shutdown, got: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("daemon did not shut down within 8s of cancellation")
	}
}
