package fleet

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	db, err := sql.Open("sqlite", "file:revoke_"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestRevokeUnrevokeRoundTrip(t *testing.T) {
	r := newTestRegistry(t)
	if err := r.AddPending(&Device{DeviceID: "DEV1", Role: "reader"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if r.IsRevoked("DEV1") {
		t.Fatal("new device should not be revoked")
	}
	if err := r.Revoke("DEV1", "stolen laptop"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !r.IsRevoked("DEV1") {
		t.Fatal("device should be revoked")
	}
	d, err := r.Get("DEV1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !d.Revoked || d.RevokedReason != "stolen laptop" || d.RevokedAt.IsZero() {
		t.Fatalf("revocation fields not persisted: %+v", d)
	}
	if err := r.Unrevoke("DEV1"); err != nil {
		t.Fatalf("Unrevoke: %v", err)
	}
	if r.IsRevoked("DEV1") {
		t.Fatal("device should be un-revoked")
	}
}

func TestRevokeUnknownDeviceFails(t *testing.T) {
	r := newTestRegistry(t)
	if err := r.Revoke("NOPE", ""); err == nil {
		t.Fatal("expected error revoking unknown device")
	}
}

func TestMigrationAddsRevokedColumnsToExistingDB(t *testing.T) {
	db, err := sql.Open("sqlite", "file:legacy?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Create a pre-revocation table (no revoked columns), then construct the
	// registry which must add them via the additive migration.
	_, err = db.Exec(`CREATE TABLE fleet_devices (
		device_id TEXT PRIMARY KEY, hostname TEXT, os TEXT, arch TEXT, role TEXT,
		status TEXT, address TEXT, cert_pem BLOB, last_seen_at INTEGER,
		created_at INTEGER, metadata TEXT, ca_fingerprint TEXT, ca_cert_pem BLOB)`)
	if err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	r, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry on legacy db: %v", err)
	}
	if err := r.AddPending(&Device{DeviceID: "X", Role: "reader"}); err != nil {
		t.Fatalf("AddPending after migration: %v", err)
	}
	if r.IsRevoked("X") {
		t.Fatal("migrated row should default to not-revoked")
	}
}
