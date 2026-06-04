package grpc

import (
	"context"
	"strings"

	"github.com/inovacc/sentinel/internal/limits"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// isMsgSizeExhausted reports whether err is a ResourceExhausted status raised by
// grpc-go's MaxRecvMsgSize enforcement (as opposed to, e.g., the rate limiter,
// which also uses ResourceExhausted). grpc-go formats the message as
// "grpc: received message larger than max (N vs. M)", so we match on that
// signature to avoid mislabeling rate-limit rejections as msg_size breaches.
func isMsgSizeExhausted(err error) bool {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		return false
	}
	msg := st.Message()
	return strings.Contains(msg, "received message larger than max") ||
		strings.Contains(msg, "trying to send message larger than max")
}

// UnaryMsgSizeInterceptor returns a unary server interceptor that records a
// msg_size breach when grpc-go rejects an oversized inbound message
// (MaxRecvMsgSize). grpc-go enforces the cap natively and returns
// ResourceExhausted from the handler invocation; this interceptor observes that
// error, emits the breach contract (kind=msg_size, source=method), and passes
// the original error through unchanged. A nil recorder is safe.
func UnaryMsgSizeInterceptor(rec *limits.Recorder) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		resp, err := handler(ctx, req)
		if isMsgSizeExhausted(err) {
			rec.Record(ctx, limits.KindMsgSize, info.FullMethod)
		}
		return resp, err
	}
}

// StreamMsgSizeInterceptor returns a stream server interceptor that records a
// msg_size breach when grpc-go rejects an oversized message on a stream. The
// original error is passed through unchanged. A nil recorder is safe.
func StreamMsgSizeInterceptor(rec *limits.Recorder) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		err := handler(srv, ss)
		if isMsgSizeExhausted(err) {
			rec.Record(ss.Context(), limits.KindMsgSize, info.FullMethod)
		}
		return err
	}
}

// WithMsgSizeRecorder returns an Option that adds the msg_size breach-detecting
// interceptors (unary and stream) to the gRPC server interceptor chain. It pairs
// with WithMaxRecvMsgSize: the latter enforces the cap, the former records the
// breach. A nil recorder is safe (the interceptors become observe-only no-ops).
func WithMsgSizeRecorder(rec *limits.Recorder) Option {
	return func(c *serverConfig) {
		c.extraUnaryInterceptors = append(c.extraUnaryInterceptors, UnaryMsgSizeInterceptor(rec))
		c.extraStreamInterceptors = append(c.extraStreamInterceptors, StreamMsgSizeInterceptor(rec))
	}
}
