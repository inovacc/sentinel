package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/sentinel/internal/settings"
)

func TestCheckConfigAt(t *testing.T) {
	t.Run("missing file without --fix warns", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		res, _ := checkConfigAt(path, false)
		if res.status != stWarn {
			t.Errorf("status = %s, want WARN (%s)", res.status, res.detail)
		}
	})

	t.Run("missing file with --fix creates current version", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		res, _ := checkConfigAt(path, true)
		if res.status != stFixed {
			t.Fatalf("status = %s, want FIXED (%s)", res.status, res.detail)
		}
		if v, _ := settings.OnDiskVersion(path); v != settings.CurrentConfigVersion {
			t.Errorf("written version = %d, want %d", v, settings.CurrentConfigVersion)
		}
	})

	t.Run("unversioned migrates with --fix", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("listen:\n  grpc: \":7400\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if res, _ := checkConfigAt(path, false); res.status != stWarn {
			t.Errorf("dry-run status = %s, want WARN (%s)", res.status, res.detail)
		}
		res, _ := checkConfigAt(path, true)
		if res.status != stFixed {
			t.Fatalf("fix status = %s, want FIXED (%s)", res.status, res.detail)
		}
		if v, _ := settings.OnDiskVersion(path); v != settings.CurrentConfigVersion {
			t.Errorf("migrated version = %d, want %d", v, settings.CurrentConfigVersion)
		}
	})

	t.Run("current version is OK", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := settings.Save(path, settings.DefaultConfig()); err != nil {
			t.Fatal(err)
		}
		if res, _ := checkConfigAt(path, false); res.status != stOK {
			t.Errorf("status = %s, want OK (%s)", res.status, res.detail)
		}
	})

	t.Run("invalid config fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("listen:\n  grpc: \"not-an-address\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if res, _ := checkConfigAt(path, false); res.status != stFail {
			t.Errorf("status = %s, want FAIL (%s)", res.status, res.detail)
		}
	})
}

// TestDoctorRunsOnHealthyEnv runs the full doctor against the package test
// environment (CA + device cert + config set up by TestMain) with --fix, and
// expects no unresolved problems.
func TestDoctorRunsOnHealthyEnv(t *testing.T) {
	var buf bytes.Buffer
	if err := runDoctor(&buf, true); err != nil {
		t.Fatalf("doctor --fix reported unresolved problems: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"data directory", "config", "certificate authority", "device certificate", "listen ports"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output is missing the %q check:\n%s", want, out)
		}
	}
}
