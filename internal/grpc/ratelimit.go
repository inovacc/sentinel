package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RateLimiter implements a simple per-client token bucket rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*bucket
	rate     int
	interval time.Duration
}

type bucket struct {
	tokens   int
	lastFill time.Time
}

// NewRateLimiter creates a rate limiter that allows rate requests per interval.
// For example, NewRateLimiter(100, time.Second) allows 100 requests per second.
func NewRateLimiter(rate int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		clients:  make(map[string]*bucket),
		rate:     rate,
		interval: interval,
	}
}

// Allow checks whether clientID may proceed. It consumes one token and returns
// false when the bucket is empty (rate exceeded).
func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.clients[clientID]
	if !ok {
		b = &bucket{tokens: rl.rate, lastFill: now}
		rl.clients[clientID] = b
	}

	// Refill tokens if the interval has elapsed.
	elapsed := now.Sub(b.lastFill)
	if elapsed >= rl.interval {
		intervals := int(elapsed / rl.interval)
		b.tokens += intervals * rl.rate
		if b.tokens > rl.rate {
			b.tokens = rl.rate
		}
		b.lastFill = b.lastFill.Add(time.Duration(intervals) * rl.interval)
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// clientIDFromContext extracts a client identifier from the peer certificate
// in the gRPC context. It uses a truncated SHA-256 of the raw certificate DER
// bytes so we don't depend on the ca package here. Falls back to "unknown" if
// extraction fails.
func clientIDFromContext(ctx context.Context) string {
	cert, err := extractPeerCert(ctx)
	if err != nil {
		return "unknown"
	}
	// Use the certificate's common name if available, otherwise hash the DER.
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:8])
}

// UnaryRateLimitInterceptor returns a gRPC unary server interceptor that
// enforces per-client rate limits. When the limit is exceeded it returns
// codes.ResourceExhausted.
func UnaryRateLimitInterceptor(rl *RateLimiter) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		clientID := clientIDFromContext(ctx)
		if !rl.Allow(clientID) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", clientID)
		}
		return handler(ctx, req)
	}
}

// StreamRateLimitInterceptor returns a gRPC stream server interceptor that
// enforces per-client rate limits. When the limit is exceeded it returns
// codes.ResourceExhausted.
func StreamRateLimitInterceptor(rl *RateLimiter) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		clientID := clientIDFromContext(ss.Context())
		if !rl.Allow(clientID) {
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", clientID)
		}
		return handler(srv, ss)
	}
}

// WithRateLimiter returns an Option that adds rate limiting interceptors
// (both unary and stream) to the gRPC server interceptor chain.
func WithRateLimiter(rl *RateLimiter) Option {
	return func(c *serverConfig) {
		c.extraUnaryInterceptors = append(c.extraUnaryInterceptors, UnaryRateLimitInterceptor(rl))
		c.extraStreamInterceptors = append(c.extraStreamInterceptors, StreamRateLimitInterceptor(rl))
	}
}
