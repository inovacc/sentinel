//go:build !windows

package audit

import (
	"path/filepath"
	"testing"
)

func TestDBFileIs0600Unix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(Options{DBPath: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	fi, err := statFile(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("db perms = %o, want 600", perm)
	}
}
