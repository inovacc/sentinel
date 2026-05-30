package fleet

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// TestHealthMonitorOnDeviceOffline verifies the offline callback fires when a
// device is unreachable. A device with an empty address fails pingDevice
// immediately, so the check needs no network.
func TestHealthMonitorOnDeviceOffline(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// Online device with no address -> ping fails with "no address configured".
	if err := reg.AddPending(&Device{DeviceID: "DEV-OFF", Hostname: "h", Role: "operator"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if err := reg.Accept("DEV-OFF", "operator"); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	h := NewHealthMonitor(reg, t.TempDir(), slog.Default(), time.Minute)
	var got string
	h.SetOnDeviceOffline(func(id string) { got = id })

	h.checkAll(context.Background())

	if got != "DEV-OFF" {
		t.Fatalf("onDeviceOffline called with %q, want %q", got, "DEV-OFF")
	}

	// The device should also be marked offline in the registry.
	offline, err := reg.List(StatusOffline)
	if err != nil {
		t.Fatalf("List offline: %v", err)
	}
	if len(offline) != 1 || offline[0].DeviceID != "DEV-OFF" {
		t.Fatalf("expected DEV-OFF to be offline, got %+v", offline)
	}
}

// TestHealthMonitorNoCallbackWhenUnset ensures a nil callback is tolerated.
func TestHealthMonitorNoCallbackWhenUnset(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.AddPending(&Device{DeviceID: "DEV-X", Role: "operator"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if err := reg.Accept("DEV-X", "operator"); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	h := NewHealthMonitor(reg, t.TempDir(), slog.Default(), time.Minute)
	// No SetOnDeviceOffline — must not panic.
	h.checkAll(context.Background())
}
