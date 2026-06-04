package audit

import (
	"context"
	"strings"
	"testing"
)

func TestTailReturnsMostRecentInOrder(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV", "admin")
	for _, et := range []string{EventCertSign, EventExecRun, EventRBACDeny} {
		if err := l.Record(ctx, Event{Type: et, Outcome: OutcomeAllow, Target: "t"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	got, err := l.Tail(Filter{Limit: 2})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("tail len = %d, want 2", len(got))
	}
	// Ascending by seq within the tail window: the last two recorded.
	if got[0].EventType != EventExecRun || got[1].EventType != EventRBACDeny {
		t.Fatalf("tail order = %s,%s; want exec.run,rbac.deny", got[0].EventType, got[1].EventType)
	}
}

func TestQueryFiltersByTypeAndOutcome(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV", "admin")
	_ = l.Record(ctx, Event{Type: EventRBACDeny, Outcome: OutcomeDeny, Target: "a"})
	_ = l.Record(ctx, Event{Type: EventExecRun, Outcome: OutcomeAllow, Target: "b"})

	got, err := l.Query(Filter{EventType: EventRBACDeny, Outcome: OutcomeDeny})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].EventType != EventRBACDeny {
		t.Fatalf("query = %+v, want one rbac.deny", got)
	}
}

func TestExportJSONContainsRecords(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV", "admin")
	_ = l.Record(ctx, Event{Type: EventCertSign, Outcome: OutcomeAllow, Target: "cn=x"})

	var sb strings.Builder
	if err := l.Export(&sb, "json", Filter{}); err != nil {
		t.Fatalf("Export json: %v", err)
	}
	if !strings.Contains(sb.String(), "cert.sign") {
		t.Fatalf("json export missing event: %s", sb.String())
	}
}

func TestExportCSVHasHeader(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV", "admin")
	_ = l.Record(ctx, Event{Type: EventExecRun, Outcome: OutcomeAllow, Target: "go"})

	var sb strings.Builder
	if err := l.Export(&sb, "csv", Filter{}); err != nil {
		t.Fatalf("Export csv: %v", err)
	}
	if !strings.HasPrefix(sb.String(), "seq,ts,actor_device_id,actor_role,event_type,outcome,target") {
		t.Fatalf("csv missing/incorrect header: %q", sb.String())
	}
}
