package fleet

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRegistry_AddPendingAndAccept(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	d := &Device{
		DeviceID: "TEST-DEVICE-1",
		Hostname: "test-host",
		OS:       "linux",
		Arch:     "amd64",
		Role:     "operator",
		Address:  "192.168.1.100:7400",
	}

	if err := reg.AddPending(d); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	// Should be pending.
	got, err := reg.Get("TEST-DEVICE-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusPending {
		t.Errorf("expected pending, got %s", got.Status)
	}
	if reg.IsTrusted("TEST-DEVICE-1") {
		t.Error("pending device should not be trusted")
	}

	// Accept.
	if err := reg.Accept("TEST-DEVICE-1", "operator"); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	got, err = reg.Get("TEST-DEVICE-1")
	if err != nil {
		t.Fatalf("Get after accept: %v", err)
	}
	if got.Status != StatusOnline {
		t.Errorf("expected online, got %s", got.Status)
	}
	if got.Role != "operator" {
		t.Errorf("expected operator, got %s", got.Role)
	}
	if !reg.IsTrusted("TEST-DEVICE-1") {
		t.Error("accepted device should be trusted")
	}
}

func TestRegistry_Reject(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	d := &Device{DeviceID: "REJECT-ME", Hostname: "bad"}
	if err := reg.AddPending(d); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	if err := reg.Reject("REJECT-ME"); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	_, err = reg.Get("REJECT-ME")
	if err == nil {
		t.Error("expected error getting rejected device")
	}
}

func TestRegistry_List(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	for _, id := range []string{"A", "B", "C"} {
		if err := reg.AddPending(&Device{DeviceID: id, Hostname: id}); err != nil {
			t.Fatalf("AddPending %s: %v", id, err)
		}
	}
	if err := reg.Accept("A", "admin"); err != nil {
		t.Fatalf("Accept A: %v", err)
	}

	// All devices.
	all, err := reg.List("")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3, got %d", len(all))
	}

	// Only pending.
	pending, err := reg.List(StatusPending)
	if err != nil {
		t.Fatalf("List pending: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("expected 2 pending, got %d", len(pending))
	}

	// Count.
	count, err := reg.Count("")
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

func TestRegistry_Remove(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	if err := reg.AddPending(&Device{DeviceID: "RM-ME"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if err := reg.Accept("RM-ME", "reader"); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err := reg.Remove("RM-ME"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	_, err = reg.Get("RM-ME")
	if err == nil {
		t.Error("expected error getting removed device")
	}
}

func TestRegistry_SetOffline(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	if err := reg.AddPending(&Device{DeviceID: "OFF"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if err := reg.Accept("OFF", "reader"); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err := reg.SetOffline("OFF"); err != nil {
		t.Fatalf("SetOffline: %v", err)
	}

	got, err := reg.Get("OFF")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusOffline {
		t.Errorf("expected offline, got %s", got.Status)
	}
	// Offline but still trusted.
	if !reg.IsTrusted("OFF") {
		t.Error("offline device should still be trusted")
	}
}
