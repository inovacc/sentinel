package fleet

import (
	"testing"
)

func TestRegistry_AddPendingPersistsCAPin(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	d := &Device{
		DeviceID:      "PIN-DEV-1",
		Address:       "10.0.0.5:7400",
		CAFingerprint: "sha256:deadbeef",
		CACertPEM:     []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
	}
	if err := reg.AddPending(d); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	got, err := reg.Get("PIN-DEV-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CAFingerprint != "sha256:deadbeef" {
		t.Errorf("CAFingerprint = %q, want sha256:deadbeef", got.CAFingerprint)
	}
	if string(got.CACertPEM) != string(d.CACertPEM) {
		t.Errorf("CACertPEM round-trip mismatch: got %q", string(got.CACertPEM))
	}
}

func TestRegistry_CAPinSurvivesList(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.AddPending(&Device{DeviceID: "L1", CAFingerprint: "sha256:aaaa"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	list, err := reg.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 device, got %d", len(list))
	}
	if list[0].CAFingerprint != "sha256:aaaa" {
		t.Errorf("List CAFingerprint = %q, want sha256:aaaa", list[0].CAFingerprint)
	}
}

func TestRegistry_SetCAPin(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.AddPending(&Device{DeviceID: "SP-1"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	pem := []byte("-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----\n")
	if err := reg.SetCAPin("SP-1", "sha256:cafe", pem); err != nil {
		t.Fatalf("SetCAPin: %v", err)
	}

	got, err := reg.Get("SP-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CAFingerprint != "sha256:cafe" {
		t.Errorf("CAFingerprint = %q, want sha256:cafe", got.CAFingerprint)
	}
	if string(got.CACertPEM) != string(pem) {
		t.Errorf("CACertPEM mismatch after SetCAPin")
	}
}

func TestRegistry_SetCAPinUnknownDevice(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.SetCAPin("does-not-exist", "sha256:x", nil); err == nil {
		t.Fatal("expected error setting pin on unknown device, got nil")
	}
}

// TestRegistry_MigratesLegacyTable verifies the additive migration: a database
// created before the CA-pin columns existed must be upgraded in place without
// data loss, and rows must remain readable with empty pin fields.
func TestRegistry_MigratesLegacyTable(t *testing.T) {
	db := testDB(t)

	// Create the legacy schema (pre-CA-pin: 11 columns, no ca_fingerprint/ca_cert_pem).
	const legacy = `
CREATE TABLE fleet_devices (
    device_id    TEXT PRIMARY KEY,
    hostname     TEXT NOT NULL DEFAULT '',
    os           TEXT NOT NULL DEFAULT '',
    arch         TEXT NOT NULL DEFAULT '',
    role         TEXT NOT NULL DEFAULT 'reader',
    status       TEXT NOT NULL DEFAULT 'pending',
    address      TEXT NOT NULL DEFAULT '',
    cert_pem     BLOB,
    last_seen_at INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    metadata     TEXT DEFAULT '{}'
);
INSERT INTO fleet_devices (device_id, last_seen_at, created_at)
VALUES ('LEGACY-1', 0, 0);
`
	if _, err := db.Exec(legacy); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}

	// NewRegistry must migrate the legacy table in place.
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry on legacy db: %v", err)
	}

	// Legacy row must still be readable, with empty pin.
	got, err := reg.Get("LEGACY-1")
	if err != nil {
		t.Fatalf("Get legacy row after migration: %v", err)
	}
	if got.CAFingerprint != "" {
		t.Errorf("legacy row CAFingerprint = %q, want empty", got.CAFingerprint)
	}

	// New writes that use the pin must work on the migrated table.
	if err := reg.SetCAPin("LEGACY-1", "sha256:beef", nil); err != nil {
		t.Fatalf("SetCAPin on migrated row: %v", err)
	}
	got, err = reg.Get("LEGACY-1")
	if err != nil {
		t.Fatalf("Get after SetCAPin: %v", err)
	}
	if got.CAFingerprint != "sha256:beef" {
		t.Errorf("CAFingerprint = %q, want sha256:beef", got.CAFingerprint)
	}
}
