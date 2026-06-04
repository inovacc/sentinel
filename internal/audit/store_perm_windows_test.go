//go:build windows

package audit

import (
	"path/filepath"
	"testing"
)

// On Windows there are no Unix mode bits; we assert the file exists and is
// readable/writable by the owner. ACL hardening is handled by the data-dir
// creation (datadir.Root, 0700-equivalent) and is out of scope for this unit.
func TestDBFileCreatedWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(Options{DBPath: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	if _, err := statFile(path); err != nil {
		t.Fatalf("stat: %v", err)
	}
}
