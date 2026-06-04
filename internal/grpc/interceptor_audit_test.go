package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
)

// recordingLogger captures emitted events and can be made to fail.
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

func TestAuditEventForMethodTier(t *testing.T) {
	tests := []struct {
		method  string
		role    string
		allowed bool
		want    string
	}{
		{"/sentinel.v1.FleetService/AcceptPairing", "admin", true, audit.EventRBACAllowPrivileged},
		{"/sentinel.v1.FileSystemService/ReadFile", "reader", true, audit.EventRBACAllowRead},
		{"/sentinel.v1.ExecService/Exec", "reader", false, audit.EventRBACDeny},
	}
	for _, tt := range tests {
		got := auditEventForMethod(tt.method, tt.allowed)
		if got != tt.want {
			t.Errorf("method %s allowed=%v: event = %s, want %s", tt.method, tt.allowed, got, tt.want)
		}
	}
}

func TestCriticalAuditFailureBlocksAllow(t *testing.T) {
	rec := &recordingLogger{failOn: map[string]bool{audit.EventRBACAllowPrivileged: true}}
	// emitAccessAudit must return an error when a critical event fails to write,
	// so the interceptor aborts the privileged call (fail-closed).
	err := emitAccessAudit(context.Background(), rec,
		"/sentinel.v1.FleetService/AcceptPairing", "admin", true)
	if err == nil {
		t.Fatal("critical audit write failure must block the operation")
	}
}

func TestRoutineAuditFailureDoesNotBlock(t *testing.T) {
	rec := &recordingLogger{failOn: map[string]bool{audit.EventRBACAllowRead: true}}
	err := emitAccessAudit(context.Background(), rec,
		"/sentinel.v1.FileSystemService/ReadFile", "reader", true)
	if err != nil {
		t.Fatalf("routine audit write failure must not block: %v", err)
	}
}
