package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigIsCurrentVersion(t *testing.T) {
	if v := DefaultConfig().Version; v != CurrentConfigVersion {
		t.Errorf("DefaultConfig().Version = %d, want %d", v, CurrentConfigVersion)
	}
}

func TestOnDiskVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Missing file -> version 0, no error.
	if v, err := OnDiskVersion(path); err != nil || v != 0 {
		t.Fatalf("missing file: got (%d, %v), want (0, nil)", v, err)
	}

	// File without a version key -> 0 (a pre-versioning config).
	if err := os.WriteFile(path, []byte("listen:\n  grpc: \":7400\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := OnDiskVersion(path); err != nil || v != 0 {
		t.Errorf("no version key: got (%d, %v), want (0, nil)", v, err)
	}

	// Explicit version.
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := OnDiskVersion(path); err != nil || v != 1 {
		t.Errorf("explicit version: got (%d, %v), want (1, nil)", v, err)
	}
}

func TestMigrateStampsVersion(t *testing.T) {
	c := DefaultConfig()
	c.Version = 0 // simulate a pre-versioning config

	if !c.Migrate() {
		t.Fatal("Migrate() should report a change for an out-of-date version")
	}
	if c.Version != CurrentConfigVersion {
		t.Errorf("after Migrate, Version = %d, want %d", c.Version, CurrentConfigVersion)
	}
	if c.Migrate() {
		t.Error("Migrate() should be a no-op the second time")
	}
}

func TestSaveLoadRoundTripPreservesVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, DefaultConfig()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	v, err := OnDiskVersion(path)
	if err != nil {
		t.Fatalf("OnDiskVersion: %v", err)
	}
	if v != CurrentConfigVersion {
		t.Errorf("saved config version on disk = %d, want %d", v, CurrentConfigVersion)
	}
}
