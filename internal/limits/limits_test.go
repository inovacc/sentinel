package limits

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/metrics"
)

type capturingLogger struct {
	events []audit.Event
	err    error
}

func (c *capturingLogger) Record(_ context.Context, ev audit.Event) error {
	c.events = append(c.events, ev)
	return c.err
}
func (c *capturingLogger) Close() error { return nil }

func TestRecordEmitsRoutineEventAndBumpsMetric(t *testing.T) {
	log := &capturingLogger{}
	r := NewRecorder(log)
	before := metricsTotalForTest()

	r.Record(context.Background(), KindBootstrapIP, "203.0.113.7")

	if len(log.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(log.events))
	}
	ev := log.events[0]
	if ev.Type != audit.EventLimitExceeded {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventLimitExceeded)
	}
	if ev.Detail["kind"] != KindBootstrapIP || ev.Detail["source"] != "203.0.113.7" {
		t.Errorf("detail = %v, want kind/source set", ev.Detail)
	}
	if got := metricsTotalForTest() - before; got != 1 {
		t.Errorf("metric delta = %d, want 1", got)
	}
}

func TestRecordSwallowsAuditError(t *testing.T) {
	// A routine audit-write failure must not panic or propagate; the rejection
	// (caller's responsibility) proceeds regardless.
	log := &capturingLogger{err: errors.New("disk full")}
	r := NewRecorder(log)
	r.Record(context.Background(), KindRPCRate, "device-x") // must not panic
}

func TestNilRecorderIsSafe(t *testing.T) {
	var r *Recorder
	r.Record(context.Background(), KindMsgSize, "x") // must be a no-op, no panic
}

// metricsTotalForTest reads the global counter via a fresh handler scrape proxy.
func metricsTotalForTest() uint64 { return metrics.LimitExceededTotalForTest() }
