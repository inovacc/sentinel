package transport

import (
	"testing"
	"time"
)

func TestCertStore_BootstrapLifecycle(t *testing.T) {
	dir := t.TempDir()

	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	// Initially no certs.
	if store.HasBootstrap() {
		t.Error("expected no bootstrap certs initially")
	}
	if store.HasMTLS() {
		t.Error("expected no mTLS certs initially")
	}

	// Save bootstrap.
	cert, key, err := GenerateBootstrapIdentity()
	if err != nil {
		t.Fatalf("GenerateBootstrapIdentity: %v", err)
	}

	if err := store.SaveBootstrap(cert, key); err != nil {
		t.Fatalf("SaveBootstrap: %v", err)
	}

	if !store.HasBootstrap() {
		t.Error("expected bootstrap certs after save")
	}

	// Load bootstrap.
	loadedCert, loadedKey, err := store.LoadBootstrap()
	if err != nil {
		t.Fatalf("LoadBootstrap: %v", err)
	}

	if string(loadedCert) != string(cert) {
		t.Error("bootstrap cert mismatch")
	}
	if string(loadedKey) != string(key) {
		t.Error("bootstrap key mismatch")
	}

	// Clear bootstrap.
	if err := store.ClearBootstrap(); err != nil {
		t.Fatalf("ClearBootstrap: %v", err)
	}

	if store.HasBootstrap() {
		t.Error("expected no bootstrap certs after clear")
	}
}

func TestCertStore_MTLSLifecycle(t *testing.T) {
	ts := newTestSetup(t)
	dir := t.TempDir()

	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	caCertPEM := ts.CA.RootCertPEM()

	// Save mTLS.
	if err := store.SaveMTLS(ts.DeviceCert, ts.DeviceKey, caCertPEM); err != nil {
		t.Fatalf("SaveMTLS: %v", err)
	}

	if !store.HasMTLS() {
		t.Error("expected mTLS certs after save")
	}

	// Load mTLS.
	loadedCert, loadedKey, loadedCA, err := store.LoadMTLS()
	if err != nil {
		t.Fatalf("LoadMTLS: %v", err)
	}

	if string(loadedCert) != string(ts.DeviceCert) {
		t.Error("device cert mismatch")
	}
	if string(loadedKey) != string(ts.DeviceKey) {
		t.Error("device key mismatch")
	}
	if string(loadedCA) != string(caCertPEM) {
		t.Error("CA cert mismatch")
	}
}

func TestCertStore_NeedsRenewal(t *testing.T) {
	ts := newTestSetup(t)
	dir := t.TempDir()

	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	caCertPEM := ts.CA.RootCertPEM()

	if err := store.SaveMTLS(ts.DeviceCert, ts.DeviceKey, caCertPEM); err != nil {
		t.Fatalf("SaveMTLS: %v", err)
	}

	// Device cert valid for 1 year, so it should NOT need renewal within 30 days.
	needs, err := store.NeedsRenewal(30)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if needs {
		t.Error("expected no renewal needed for fresh cert")
	}

	// But it SHOULD need renewal within 400 days (cert valid for 365).
	needs, err = store.NeedsRenewal(400)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if !needs {
		t.Error("expected renewal needed within 400 days for 365-day cert")
	}
}

func TestCertStore_Dir(t *testing.T) {
	dir := t.TempDir()

	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	if store.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", store.Dir(), dir)
	}
}

func TestMTLSDialer(t *testing.T) {
	ts := newTestSetup(t)

	cfg := MTLSConfig{
		CertPEM:   ts.DeviceCert,
		KeyPEM:    ts.DeviceKey,
		CACertPEM: ts.CA.RootCertPEM(),
	}

	dialer, err := NewMTLSDialer(cfg)
	if err != nil {
		t.Fatalf("NewMTLSDialer: %v", err)
	}

	if dialer.TLSConfig() == nil {
		t.Error("expected non-nil TLS config")
	}

	// Verify TLS config has correct min version.
	if dialer.TLSConfig().MinVersion != 0x0304 { // TLS 1.3
		t.Errorf("expected TLS 1.3, got 0x%04x", dialer.TLSConfig().MinVersion)
	}
}

func TestMTLSServerConfig(t *testing.T) {
	ts := newTestSetup(t)

	cfg := MTLSConfig{
		CertPEM:   ts.DeviceCert,
		KeyPEM:    ts.DeviceKey,
		CACertPEM: ts.CA.RootCertPEM(),
	}

	tlsCfg, err := NewMTLSServerConfig(cfg)
	if err != nil {
		t.Fatalf("NewMTLSServerConfig: %v", err)
	}

	if tlsCfg.ClientAuth != 4 { // tls.RequireAndVerifyClientCert
		t.Errorf("expected RequireAndVerifyClientCert, got %d", tlsCfg.ClientAuth)
	}

	if tlsCfg.MinVersion != 0x0304 {
		t.Errorf("expected TLS 1.3, got 0x%04x", tlsCfg.MinVersion)
	}
}

func TestDaysToDuration(t *testing.T) {
	tests := []struct {
		days int
		want time.Duration
	}{
		{1, 24 * time.Hour},
		{30, 30 * 24 * time.Hour},
		{365, 365 * 24 * time.Hour},
		{0, 0},
	}

	for _, tt := range tests {
		if got := daysToDuration(tt.days); got != tt.want {
			t.Errorf("daysToDuration(%d) = %v, want %v", tt.days, got, tt.want)
		}
	}
}
