package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/limits"
	"github.com/inovacc/sentinel/internal/metrics"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// recordingLogger (with its events field, Record, and Close) is defined in
// interceptor_audit_test.go; this file only adds the `last` helper below.
func (r *recordingLogger) last(kind string) (audit.Event, bool) {
	for i := len(r.events) - 1; i >= 0; i-- {
		if d, ok := r.events[i].Detail["kind"]; ok && d == kind {
			return r.events[i], true
		}
	}
	return audit.Event{}, false
}

// TestUnaryRateLimitInterceptorEmitsRPCRate proves the unary rate-limit reject
// path records an rpc_rate breach (event kind + metric bump) carrying the client
// id as source, and that a nil recorder is safe.
func TestUnaryRateLimitInterceptorEmitsRPCRate(t *testing.T) {
	log := &recordingLogger{}
	rec := limits.NewRecorder(log)
	rl := NewRateLimiter(1, time.Hour) // one token, never refills within the test
	interceptor := UnaryRateLimitInterceptor(rl, rec)

	handler := func(_ context.Context, _ any) (any, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
	ctx := context.Background()

	// First call consumes the only token and succeeds (no breach).
	if _, err := interceptor(ctx, nil, info, handler); err != nil {
		t.Fatalf("first call: %v", err)
	}

	before := metrics.LimitExceededTotalForTest()

	// Second call is rate-limited: must return ResourceExhausted and emit a breach.
	_, err := interceptor(ctx, nil, info, handler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted, got %v", err)
	}
	if got := metrics.LimitExceededTotalForTest() - before; got != 1 {
		t.Fatalf("metric delta = %d, want 1", got)
	}
	ev, ok := log.last(limits.KindRPCRate)
	if !ok {
		t.Fatal("expected an rpc_rate breach event")
	}
	if ev.Type != audit.EventLimitExceeded || ev.Detail["source"] != clientIDFromContext(ctx) {
		t.Fatalf("breach event = %+v, want type=%s source=%s", ev, audit.EventLimitExceeded, clientIDFromContext(ctx))
	}
}

// TestStreamRateLimitInterceptorEmitsRPCRate proves the stream reject path emits.
func TestStreamRateLimitInterceptorEmitsRPCRate(t *testing.T) {
	log := &recordingLogger{}
	rec := limits.NewRecorder(log)
	rl := NewRateLimiter(1, time.Hour)
	interceptor := StreamRateLimitInterceptor(rl, rec)

	handler := func(_ any, _ grpc.ServerStream) error { return nil }
	info := &grpc.StreamServerInfo{FullMethod: "/svc/Stream"}
	ss := &fakeServerStream{ctx: context.Background()}

	if err := interceptor(nil, ss, info, handler); err != nil {
		t.Fatalf("first call: %v", err)
	}

	before := metrics.LimitExceededTotalForTest()
	err := interceptor(nil, ss, info, handler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted, got %v", err)
	}
	if got := metrics.LimitExceededTotalForTest() - before; got != 1 {
		t.Fatalf("metric delta = %d, want 1", got)
	}
	if _, ok := log.last(limits.KindRPCRate); !ok {
		t.Fatal("expected an rpc_rate breach event")
	}
}

// TestRateLimitNilRecorderSafe proves a nil recorder does not panic and still
// enforces the limit.
func TestRateLimitNilRecorderSafe(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour)
	interceptor := UnaryRateLimitInterceptor(rl, nil)
	handler := func(_ context.Context, _ any) (any, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
	_, _ = interceptor(context.Background(), nil, info, handler)
	if _, err := interceptor(context.Background(), nil, info, handler); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("nil recorder must still enforce the limit, got %v", err)
	}
}

// fakeServerStream is a minimal grpc.ServerStream carrying a context.
type fakeServerStream struct {
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context      { return f.ctx }
func (f *fakeServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (f *fakeServerStream) SendHeader(_ metadata.MD) error { return nil }
func (f *fakeServerStream) SetTrailer(_ metadata.MD)       {}
func (f *fakeServerStream) SendMsg(_ any) error            { return nil }
func (f *fakeServerStream) RecvMsg(_ any) error            { return nil }

var _ grpc.ServerStream = (*fakeServerStream)(nil)
