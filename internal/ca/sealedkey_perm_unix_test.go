//go:build !windows

package ca

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/sentinel/internal/security/crypto"
)

func TestMigrateBackupIs0600Unix(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	keyPath := filepath.Join(dir, caKeyFile)

	sealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	if _, err := MigrateKeyAtRest(dir, sealer); err != nil {
		t.Fatalf("MigrateKeyAtRest: %v", err)
	}

	fi, err := os.Stat(keyPath + ".plaintext.bak")
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, want 0600", fi.Mode().Perm())
	}
}
