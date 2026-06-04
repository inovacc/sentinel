package ca

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/sentinel/internal/security/crypto"
)

func TestLoadWithSealerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})

	c, err := InitWithSealer(dir, sealer)
	if err != nil {
		t.Fatalf("InitWithSealer: %v", err)
	}
	_ = c

	// The on-disk key must be an encrypted envelope, not plaintext PEM.
	raw, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !crypto.IsEnvelope(raw) {
		t.Fatal("ca.key is not encrypted on disk")
	}

	// Reload with the same sealer must succeed.
	if _, err := LoadWithSealer(dir, sealer); err != nil {
		t.Fatalf("LoadWithSealer: %v", err)
	}
}

func TestLoadRejectsSwappedCert(t *testing.T) {
	dir := t.TempDir()
	sealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	if _, err := InitWithSealer(dir, sealer); err != nil {
		t.Fatalf("InitWithSealer: %v", err)
	}

	// Overwrite ca.crt with an unrelated CA's cert (different public key).
	other := t.TempDir()
	otherSealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	oc, _ := InitWithSealer(other, otherSealer)
	if err := os.WriteFile(filepath.Join(dir, caCertFile), oc.RootCertPEM(), 0o644); err != nil {
		t.Fatalf("swap cert: %v", err)
	}

	if _, err := LoadWithSealer(dir, sealer); err == nil {
		t.Fatal("expected cert/key public-key mismatch to fail load")
	}
}

func TestLoadFailsClosedOnWrongSealer(t *testing.T) {
	dir := t.TempDir()
	good, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	if _, err := InitWithSealer(dir, good); err != nil {
		t.Fatalf("InitWithSealer: %v", err)
	}
	// A different keystore → different DEK → cannot unseal.
	wrong, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	if _, err := LoadWithSealer(dir, wrong); err == nil {
		t.Fatal("expected unseal failure with wrong sealer")
	}
	// The plaintext key must NOT have been regenerated.
	if _, err := os.Stat(filepath.Join(dir, caKeyFile+".plaintext.bak")); err == nil {
		t.Fatal("load must not create a plaintext backup")
	}
}
