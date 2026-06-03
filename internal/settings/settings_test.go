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

	if !c.Migrate(0) {
		t.Fatal("Migrate() should report a change for an out-of-date version")
	}
	if c.Version != CurrentConfigVersion {
		t.Errorf("after Migrate, Version = %d, want %d", c.Version, CurrentConfigVersion)
	}
	if c.Migrate(CurrentConfigVersion) {
		t.Error("Migrate() should be a no-op the second time")
	}
}

// TestMigrateAddsConfineBlockToPreV2Config is the central Task-2 deliverable:
// loading a pre-v2 config file that has no confine: key yields a fully populated
// confine block (supplied by Load's overlay onto DefaultConfig), the version is
// stamped to current by Migrate, and the result survives a Save/Load round-trip.
func TestMigrateAddsConfineBlockToPreV2Config(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// A v1 file with no confine: key at all.
	const preV2 = "version: 1\nlisten:\n  grpc: \":7400\"\n"
	if err := os.WriteFile(path, []byte(preV2), 0o600); err != nil {
		t.Fatal(err)
	}

	diskVer, err := OnDiskVersion(path)
	if err != nil {
		t.Fatalf("OnDiskVersion: %v", err)
	}
	if diskVer != 1 {
		t.Fatalf("OnDiskVersion = %d, want 1", diskVer)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Migrate(diskVer) {
		t.Fatal("Migrate(1) should report a change for a pre-v2 config")
	}

	want := defaultConfineConfig()
	if cfg.Confine != want {
		t.Errorf("after Migrate, Confine = %+v, want %+v", cfg.Confine, want)
	}
	if cfg.Version != CurrentConfigVersion {
		t.Errorf("after Migrate, Version = %d, want %d", cfg.Version, CurrentConfigVersion)
	}

	// Round-trip: the populated block must persist on disk and reload intact.
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Confine != want {
		t.Errorf("after round-trip, Confine = %+v, want %+v", reloaded.Confine, want)
	}
}

// TestMigratePreservesExplicitConfineDisable covers the intent-override finding.
// A v1 file that explicitly disables confinement (confine.enabled: false) must
// NOT be re-enabled by migration. Because Load overlays YAML onto DefaultConfig,
// the numeric fields keep their defaults while enabled stays false — and the
// version-gated migration leaves that explicit toggle alone.
func TestMigratePreservesExplicitConfineDisable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	const disabled = "version: 1\nconfine:\n  enabled: false\n"
	if err := os.WriteFile(path, []byte(disabled), 0o600); err != nil {
		t.Fatal(err)
	}

	diskVer, err := OnDiskVersion(path)
	if err != nil {
		t.Fatalf("OnDiskVersion: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Precondition: the user's explicit disable survived Load.
	if cfg.Confine.Enabled {
		t.Fatalf("precondition: Load did not preserve confine.enabled: false: %+v", cfg.Confine)
	}

	cfg.Migrate(diskVer)

	if cfg.Confine.Enabled {
		t.Error("migration must not re-enable confinement the user explicitly disabled")
	}

	// The same must hold through a Save/Load round-trip.
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Confine.Enabled {
		t.Error("after round-trip, confine.enabled must remain false")
	}
}

// TestMigrateLeavesCurrentConfineUntouched guards against the dead-code finding:
// a config already at the current version must not have its (possibly
// user-tuned) confine block clobbered, even if it happened to be zero-valued.
func TestMigrateLeavesCurrentConfineUntouched(t *testing.T) {
	c := DefaultConfig()
	c.Confine = ConfineConfig{} // zero value, but already current version
	if c.Migrate(CurrentConfigVersion) {
		t.Error("Migrate at current version should be a no-op")
	}
	if c.Confine != (ConfineConfig{}) {
		t.Errorf("Migrate must not default Confine for an up-to-date config: %+v", c.Confine)
	}
}

func TestDefaultConfigHasConfineDefaults(t *testing.T) {
	c := DefaultConfig()
	if !c.Confine.Enabled {
		t.Error("confine should default to enabled")
	}
	if c.Confine.MaxMemoryMB == 0 || c.Confine.MaxProcesses == 0 {
		t.Errorf("confine defaults look unset: %+v", c.Confine)
	}
}

func TestConfineValidateRejectsBadCPU(t *testing.T) {
	c := DefaultConfig()
	c.Confine.CPUPercent = 250 // > 100
	if err := c.Validate(); err == nil {
		t.Error("CPUPercent > 100 should be rejected by Validate")
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
