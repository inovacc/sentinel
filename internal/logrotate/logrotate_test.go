package logrotate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteNoRotationUnderLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	w, err := New(path, 1, 3) // 1 MB limit — well above the payload.
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	if _, err := w.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("expected no rotated file, stat err = %v", err)
	}
	if got := readFile(t, path); got != "hello\n" {
		t.Fatalf("current file = %q, want %q", got, "hello\n")
	}
}

// TestRotationShiftsAndCaps verifies that rotation renumbers files (.1 -> .2),
// keeps at most maxFiles rotated copies, and tolerates missing intermediate
// files without erroring. maxSizeMB=0 forces a rotation before every write.
func TestRotationShiftsAndCaps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	w, err := New(path, 0, 2) // maxFiles=2
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	for _, line := range []string{"one", "two", "three"} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("Write(%s): %v", line, err)
		}
	}

	cases := map[string]string{
		path:        "three", // current
		path + ".1": "two",   // most recent rotation
		path + ".2": "one",   // oldest kept
	}
	for p, want := range cases {
		if got := readFile(t, p); got != want {
			t.Errorf("%s = %q, want %q", filepath.Base(p), got, want)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("expected .3 to be capped away, stat err = %v", err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}
