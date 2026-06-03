package cmd

import (
	"strings"
	"testing"

	"github.com/inovacc/sentinel/internal/ca"
)

func TestCAPinFingerprint(t *testing.T) {
	t.Run("empty CA pins nothing, no error", func(t *testing.T) {
		fp, err := caPinFingerprint(nil)
		if err != nil {
			t.Fatalf("empty CA should not error: %v", err)
		}
		if fp != "" {
			t.Errorf("empty CA should yield empty fingerprint, got %q", fp)
		}
	})

	t.Run("unparseable non-empty CA fails closed", func(t *testing.T) {
		if _, err := caPinFingerprint([]byte("this is not a certificate PEM")); err == nil {
			t.Fatal("a non-empty but unparseable CA must return an error, not silently skip pinning")
		}
	})

	t.Run("valid CA yields a sha256 fingerprint", func(t *testing.T) {
		authority, err := ca.Init(t.TempDir())
		if err != nil {
			t.Fatalf("init CA: %v", err)
		}
		fp, err := caPinFingerprint(authority.RootCertPEM())
		if err != nil {
			t.Fatalf("valid CA: %v", err)
		}
		if !strings.HasPrefix(fp, "sha256:") {
			t.Errorf("fingerprint = %q, want sha256: prefix", fp)
		}
	})
}
