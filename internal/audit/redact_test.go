package audit

import "testing"

func TestRedactKeepsAllowlistedKeys(t *testing.T) {
	in := map[string]any{
		"command": "go",
		"argv":    []string{"go", "build"},
		"role":    "operator",
		"path":    "/x/y",
	}
	out := redactDetail(in)
	for _, k := range []string{"command", "argv", "role", "path"} {
		if _, ok := out[k]; !ok {
			t.Errorf("allowlisted key %q was dropped", k)
		}
	}
}

func TestRedactDropsUnknownKeys(t *testing.T) {
	in := map[string]any{"command": "go", "wat": "should-drop"}
	out := redactDetail(in)
	if _, ok := out["wat"]; ok {
		t.Error("non-allowlisted key was retained")
	}
}

func TestRedactReplacesSensitiveKeys(t *testing.T) {
	in := map[string]any{"private_key": "MII...", "password": "hunter2", "token": "abc"}
	out := redactDetail(in)
	for _, k := range []string{"private_key", "password", "token"} {
		v, ok := out[k]
		if !ok {
			t.Errorf("sensitive key %q dropped entirely; want redaction marker", k)
			continue
		}
		if v != "[redacted]" {
			t.Errorf("sensitive key %q = %v, want [redacted]", k, v)
		}
	}
}

func TestRedactNilIsNil(t *testing.T) {
	if out := redactDetail(nil); len(out) != 0 {
		t.Fatalf("nil detail produced %v", out)
	}
}
