package grpc

import (
	"context"
	"testing"

	"github.com/inovacc/sentinel/internal/limits"
	"github.com/inovacc/sentinel/internal/metrics"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsMsgSizeExhausted(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"recv oversized", status.Errorf(codes.ResourceExhausted, "grpc: received message larger than max (5 vs. 4)"), true},
		{"send oversized", status.Errorf(codes.ResourceExhausted, "grpc: trying to send message larger than max (5 vs. 4)"), true},
		{"rate limit exhausted", status.Errorf(codes.ResourceExhausted, "rate limit exceeded for device-x"), false},
		{"other code", status.Errorf(codes.Internal, "received message larger than max"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMsgSizeExhausted(tt.err); got != tt.want {
				t.Fatalf("isMsgSizeExhausted = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestUnaryMsgSizeInterceptorEmitsMsgSize proves an oversized-message
// ResourceExhausted from the handler triggers a msg_size breach (event + metric)
// with the method as source, while a rate-limit ResourceExhausted does not.
func TestUnaryMsgSizeInterceptorEmitsMsgSize(t *testing.T) {
	log := &recordingLogger{}
	rec := limits.NewRecorder(log)
	interceptor := UnaryMsgSizeInterceptor(rec)
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Big"}

	// Oversized message: grpc-go-style error -> breach emitted, error passes through.
	oversized := func(_ context.Context, _ any) (any, error) {
		return nil, status.Errorf(codes.ResourceExhausted, "grpc: received message larger than max (9 vs. 4)")
	}
	before := metrics.LimitExceededTotalForTest()
	_, err := interceptor(context.Background(), nil, info, oversized)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("error must pass through unchanged, got %v", err)
	}
	if got := metrics.LimitExceededTotalForTest() - before; got != 1 {
		t.Fatalf("metric delta = %d, want 1", got)
	}
	ev, ok := log.last(limits.KindMsgSize)
	if !ok {
		t.Fatal("expected a msg_size breach event")
	}
	if ev.Detail["source"] != "/svc/Big" {
		t.Fatalf("breach source = %v, want /svc/Big", ev.Detail["source"])
	}

	// A non-size ResourceExhausted (rate limiter) must NOT be mislabeled.
	rateLimited := func(_ context.Context, _ any) (any, error) {
		return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for c1")
	}
	before = metrics.LimitExceededTotalForTest()
	_, _ = interceptor(context.Background(), nil, info, rateLimited)
	if got := metrics.LimitExceededTotalForTest() - before; got != 0 {
		t.Fatalf("rate-limit error must not emit msg_size; metric delta = %d, want 0", got)
	}

	// A successful call emits nothing.
	ok2 := func(_ context.Context, _ any) (any, error) { return "fine", nil }
	before = metrics.LimitExceededTotalForTest()
	if _, err := interceptor(context.Background(), nil, info, ok2); err != nil {
		t.Fatalf("ok call: %v", err)
	}
	if got := metrics.LimitExceededTotalForTest() - before; got != 0 {
		t.Fatalf("successful call must not emit; metric delta = %d, want 0", got)
	}
}

// TestStreamMsgSizeInterceptorEmitsMsgSize proves the stream path emits.
func TestStreamMsgSizeInterceptorEmitsMsgSize(t *testing.T) {
	log := &recordingLogger{}
	rec := limits.NewRecorder(log)
	interceptor := StreamMsgSizeInterceptor(rec)
	info := &grpc.StreamServerInfo{FullMethod: "/svc/BigStream"}
	ss := &fakeServerStream{ctx: context.Background()}

	oversized := func(_ any, _ grpc.ServerStream) error {
		return status.Errorf(codes.ResourceExhausted, "grpc: received message larger than max (9 vs. 4)")
	}
	before := metrics.LimitExceededTotalForTest()
	err := interceptor(nil, ss, info, oversized)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("error must pass through, got %v", err)
	}
	if got := metrics.LimitExceededTotalForTest() - before; got != 1 {
		t.Fatalf("metric delta = %d, want 1", got)
	}
	if _, ok := log.last(limits.KindMsgSize); !ok {
		t.Fatal("expected a msg_size breach event")
	}
}

// TestMsgSizeNilRecorderSafe proves a nil recorder is a no-op (no panic).
func TestMsgSizeNilRecorderSafe(t *testing.T) {
	interceptor := UnaryMsgSizeInterceptor(nil)
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Big"}
	oversized := func(_ context.Context, _ any) (any, error) {
		return nil, status.Errorf(codes.ResourceExhausted, "grpc: received message larger than max (9 vs. 4)")
	}
	if _, err := interceptor(context.Background(), nil, info, oversized); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("error must pass through with nil recorder, got %v", err)
	}
}
