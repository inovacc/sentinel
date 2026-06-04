package ca

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/sentinel/internal/security/crypto"
)

func TestMigrateEncryptsPlaintextKey(t *testing.T) {
	dir := t.TempDir()
	// Create a plaintext CA (passthrough sealer writes PEM).
	if _, err := Init(dir); err != nil {
		t.Fatalf("Init plaintext: %v", err)
	}
	keyPath := filepath.Join(dir, caKeyFile)
	raw, _ := os.ReadFile(keyPath)
	if crypto.IsEnvelope(raw) {
		t.Fatal("precondition: key should be plaintext")
	}

	sealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	migrated, err := MigrateKeyAtRest(dir, sealer)
	if err != nil {
		t.Fatalf("MigrateKeyAtRest: %v", err)
	}
	if !migrated {
		t.Fatal("expected migration to occur")
	}
	enc, _ := os.ReadFile(keyPath)
	if !crypto.IsEnvelope(enc) {
		t.Fatal("key not encrypted after migration")
	}
	bak, err := os.ReadFile(keyPath + ".plaintext.bak")
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if !cryptoEqual(bak, raw) {
		t.Fatal("backup does not match original plaintext")
	}

	// Idempotent: a second migration is a no-op.
	again, err := MigrateKeyAtRest(dir, sealer)
	if err != nil {
		t.Fatalf("second MigrateKeyAtRest: %v", err)
	}
	if again {
		t.Fatal("second migration must be a no-op")
	}
}

func TestMigrateAbortLeavesPlaintextIntact(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	keyPath := filepath.Join(dir, caKeyFile)
	before, _ := os.ReadFile(keyPath)

	// A sealer whose keystore is unavailable cannot be constructed; simulate a
	// DEK-establishment failure by passing a nil sealer → MigrateKeyAtRest errors.
	if _, err := MigrateKeyAtRest(dir, nil); err == nil {
		t.Fatal("expected error with nil sealer")
	}
	after, _ := os.ReadFile(keyPath)
	if !cryptoEqual(before, after) {
		t.Fatal("plaintext key must be untouched on abort")
	}
}

func cryptoEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

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
