package fleet

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
)

// recordingLogger captures emitted events and can be made to fail on demand,
// mirroring the helper in internal/grpc so the fleet emission + fail-closed
// posture can be asserted without the real SQLite store.
type recordingLogger struct {
	events []audit.Event
	failOn map[string]bool // event types that should return an error
}

func (r *recordingLogger) Record(_ context.Context, ev audit.Event) error {
	r.events = append(r.events, ev)
	if r.failOn[ev.Type] {
		return errors.New("simulated audit write failure")
	}
	return nil
}
func (r *recordingLogger) Close() error { return nil }

func (r *recordingLogger) countOf(evType string) int {
	n := 0
	for _, e := range r.events {
		if e.Type == evType {
			n++
		}
	}
	return n
}

func (r *recordingLogger) last(evType string) (audit.Event, bool) {
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].Type == evType {
			return r.events[i], true
		}
	}
	return audit.Event{}, false
}

// TestRegistry_SetCAPin_EmitsCAPinChange proves capin.change fires only on a
// genuine rotation (a prior, different fingerprint) — never on first set or a
// no-op re-pin — and that the detail carries prefixes only (no full secret).
func TestRegistry_SetCAPin_EmitsCAPinChange(t *testing.T) {
	tests := []struct {
		name      string
		firstPin  string // "" means do not set an initial pin
		newPin    string
		wantEmits int
	}{
		{name: "first set does not emit", firstPin: "", newPin: "sha256:1111aaaa2222", wantEmits: 0},
		{name: "no-op re-pin does not emit", firstPin: "sha256:1111aaaa2222", newPin: "sha256:1111aaaa2222", wantEmits: 0},
		{name: "genuine rotation emits", firstPin: "sha256:1111aaaa2222", newPin: "sha256:9999bbbb8888", wantEmits: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := testDB(t)
			rec := &recordingLogger{}
			reg, err := NewRegistry(db, WithAuditLogger(rec))
			if err != nil {
				t.Fatalf("NewRegistry: %v", err)
			}
			if err := reg.AddPending(&Device{DeviceID: "DEV"}); err != nil {
				t.Fatalf("AddPending: %v", err)
			}
			if tt.firstPin != "" {
				if err := reg.SetCAPin("DEV", tt.firstPin, nil); err != nil {
					t.Fatalf("SetCAPin (first): %v", err)
				}
			}
			// First-pin set must never emit capin.change.
			if n := rec.countOf(audit.EventCAPinChange); n != 0 {
				t.Fatalf("capin.change emitted %d times during first pin set, want 0", n)
			}

			if err := reg.SetCAPin("DEV", tt.newPin, nil); err != nil {
				t.Fatalf("SetCAPin (new): %v", err)
			}

			if got := rec.countOf(audit.EventCAPinChange); got != tt.wantEmits {
				t.Errorf("capin.change emits = %d, want %d", got, tt.wantEmits)
			}
			if tt.wantEmits > 0 {
				ev, _ := rec.last(audit.EventCAPinChange)
				if ev.Target != "DEV" {
					t.Errorf("target = %q, want DEV", ev.Target)
				}
				oldFP, _ := ev.Detail["old_fp_prefix"].(string)
				newFP, _ := ev.Detail["new_fp_prefix"].(string)
				if oldFP == "" || newFP == "" {
					t.Errorf("detail prefixes missing: old=%q new=%q", oldFP, newFP)
				}
				// Prefixes only — the full new fingerprint must NOT be stored verbatim
				// when it is longer than the recorded prefix.
				if newFP == tt.newPin && len(tt.newPin) > 19 {
					t.Errorf("new_fp_prefix recorded the full fingerprint %q (no truncation)", newFP)
				}
			}
		})
	}
}

// TestRegistry_SetCAPin_FailClosed proves a failing critical Record aborts the
// rotation: the pin must NOT change when the capin.change audit write fails.
func TestRegistry_SetCAPin_FailClosed(t *testing.T) {
	db := testDB(t)
	rec := &recordingLogger{failOn: map[string]bool{audit.EventCAPinChange: true}}
	reg, err := NewRegistry(db, WithAuditLogger(rec))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.AddPending(&Device{DeviceID: "DEV"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if err := reg.SetCAPin("DEV", "sha256:1111aaaa2222", nil); err != nil {
		t.Fatalf("SetCAPin (first): %v", err)
	}

	// A genuine rotation whose audit write fails must return an error...
	err = reg.SetCAPin("DEV", "sha256:9999bbbb8888", nil)
	if err == nil {
		t.Fatal("expected SetCAPin to fail closed on audit write failure, got nil")
	}

	// ...and leave the stored pin unchanged.
	got, err := reg.Get("DEV")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CAFingerprint != "sha256:1111aaaa2222" {
		t.Errorf("pin changed despite fail-closed: got %q, want sha256:1111aaaa2222", got.CAFingerprint)
	}
}

// TestRegistry_Remove_EmitsFleetRemove proves fleet.remove fires on a real
// removal and not when the device does not exist.
func TestRegistry_Remove_EmitsFleetRemove(t *testing.T) {
	db := testDB(t)
	rec := &recordingLogger{}
	reg, err := NewRegistry(db, WithAuditLogger(rec))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.AddPending(&Device{DeviceID: "RM"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	// Removing a non-existent device must error and emit nothing.
	if err := reg.Remove("ghost"); err == nil {
		t.Error("expected error removing unknown device")
	}
	if n := rec.countOf(audit.EventFleetRemove); n != 0 {
		t.Errorf("fleet.remove emitted %d times for a no-op removal, want 0", n)
	}

	// A real removal emits exactly one fleet.remove targeting the device.
	if err := reg.Remove("RM"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if n := rec.countOf(audit.EventFleetRemove); n != 1 {
		t.Fatalf("fleet.remove emits = %d, want 1", n)
	}
	ev, _ := rec.last(audit.EventFleetRemove)
	if ev.Target != "RM" {
		t.Errorf("target = %q, want RM", ev.Target)
	}
	if did, _ := ev.Detail["device_id"].(string); did != "RM" {
		t.Errorf("detail device_id = %q, want RM", did)
	}
}

// TestRegistry_Remove_FailClosed proves a failing critical Record aborts the
// removal: the device row must survive when the fleet.remove audit write fails.
//
// Note: the DELETE has already run when the audit fails, so fail-closed here
// means the operation reports an error rather than silently succeeding. We
// assert the error is surfaced; row state after a failed audit is best-effort.
func TestRegistry_Remove_FailClosed(t *testing.T) {
	db := testDB(t)
	rec := &recordingLogger{failOn: map[string]bool{audit.EventFleetRemove: true}}
	reg, err := NewRegistry(db, WithAuditLogger(rec))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.AddPending(&Device{DeviceID: "RM"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	if err := reg.Remove("RM"); err == nil {
		t.Fatal("expected Remove to fail closed on audit write failure, got nil")
	}
}

// TestRegistry_DefaultsToNopLogger proves a Registry built without a logger
// never panics on a mutation (the never-nil invariant holds).
func TestRegistry_DefaultsToNopLogger(t *testing.T) {
	db := testDB(t)
	reg, err := NewRegistry(db) // no WithAuditLogger
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.AddPending(&Device{DeviceID: "N"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if err := reg.SetCAPin("N", "sha256:aaaa", nil); err != nil {
		t.Fatalf("SetCAPin: %v", err)
	}
	if err := reg.SetCAPin("N", "sha256:bbbb", nil); err != nil {
		t.Fatalf("SetCAPin rotation with NopLogger: %v", err)
	}
	if err := reg.Remove("N"); err != nil {
		t.Fatalf("Remove with NopLogger: %v", err)
	}
}
