package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
)

// recordingLogger captures emitted events and can be made to fail on demand.
type recordingLogger struct {
	events []audit.Event
	failOn map[string]bool
}

func (r *recordingLogger) Record(_ context.Context, ev audit.Event) error {
	r.events = append(r.events, ev)
	if r.failOn[ev.Type] {
		return errors.New("simulated audit write failure")
	}
	return nil
}
func (r *recordingLogger) Close() error { return nil }

// TestRecordPairingConflict_EmitsOnRefusal proves the connect flow records a
// critical pairing.conflict when a known peer's CA changed and re-pair is
// refused, and that the refusal error is still returned to the caller.
func TestRecordPairingConflict_EmitsOnRefusal(t *testing.T) {
	rec := &recordingLogger{}
	const msg = "refusing to re-pair PEER: its CA changed"

	err := recordPairingConflict(rec, "PEER", msg)
	if err == nil {
		t.Fatal("expected a refusal error, got nil")
	}
	if !strings.Contains(err.Error(), msg) {
		t.Errorf("error should carry the refusal message, got: %v", err)
	}

	if len(rec.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Type != audit.EventPairingConflict {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventPairingConflict)
	}
	if ev.Outcome != audit.OutcomeDeny {
		t.Errorf("outcome = %q, want deny", ev.Outcome)
	}
	if ev.Target != "PEER" {
		t.Errorf("target = %q, want PEER", ev.Target)
	}
	if reason, _ := ev.Detail["reason"].(string); reason != "ca-changed" {
		t.Errorf("detail reason = %q, want ca-changed", reason)
	}
	if did, _ := ev.Detail["device_id"].(string); did != "PEER" {
		t.Errorf("detail device_id = %q, want PEER", did)
	}
}

// TestRecordPairingConflict_FailClosed proves that when the critical
// pairing.conflict audit write fails, the returned error reflects the
// unaudited-conflict condition (fail-closed) rather than swallowing it.
func TestRecordPairingConflict_FailClosed(t *testing.T) {
	rec := &recordingLogger{failOn: map[string]bool{audit.EventPairingConflict: true}}

	err := recordPairingConflict(rec, "PEER", "refusing to re-pair PEER")
	if err == nil {
		t.Fatal("expected an error on audit write failure, got nil")
	}
	if !strings.Contains(err.Error(), "unaudited conflict") {
		t.Errorf("error should signal the unaudited conflict, got: %v", err)
	}
}
