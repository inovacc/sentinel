package cmd

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/inovacc/sentinel/internal/fleet"

	_ "modernc.org/sqlite"
)

// TestRevokeCommandMarksDevice verifies that newRevokeCmd and newUnrevokeCmd
// exist and that the underlying registry operations work correctly: a device
// marked revoked is visible as such in fleet List JSON output (the "revoked
// column" requirement), and Unrevoke clears the flag.
//
// We use an in-memory registry (same pattern as newTestRegistry in
// approval_test.go) so the test never touches disk or the real SENTINEL_DATA_DIR.
func TestRevokeCommandMarksDevice(t *testing.T) {
	// Ensure the cobra commands are constructable (compile-time guard).
	_ = newRevokeCmd()
	_ = newUnrevokeCmd()

	db, err := sql.Open("sqlite", "file:revoke_cmd_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg, err := fleet.NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	const devID = "DEV-REVOKE-CLI-1"
	if err := reg.AddPending(&fleet.Device{DeviceID: devID, Role: "reader"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	// Revoke via the registry (mirrors what cmd RunE delegates to).
	if err := reg.Revoke(devID, "cli test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Assert device is revoked.
	if !reg.IsRevoked(devID) {
		t.Fatal("expected device to be revoked after Revoke()")
	}

	// Assert fleet List JSON includes "revoked": true.
	devices, err := reg.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("expected at least one device in List()")
	}
	var found bool
	for _, d := range devices {
		if d.DeviceID == devID {
			found = true
			if !d.Revoked {
				t.Fatalf("device %s: Revoked field is false, want true", devID)
			}
		}
	}
	if !found {
		t.Fatalf("device %s not found in List()", devID)
	}

	// Verify JSON marshalling of the device carries "revoked": true (mirrors
	// fleet list output).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(devices); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"revoked": true`)) {
		t.Fatalf("fleet list JSON missing \"revoked\": true; got: %s", buf.String())
	}

	// Unrevoke and confirm the flag is cleared.
	if err := reg.Unrevoke(devID); err != nil {
		t.Fatalf("Unrevoke: %v", err)
	}
	if reg.IsRevoked(devID) {
		t.Fatal("expected device to be un-revoked after Unrevoke()")
	}
}
