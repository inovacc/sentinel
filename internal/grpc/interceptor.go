package grpc

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/rbac"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// privilegedMethods are mutating/admin RPCs whose successful authorization is a
// CRITICAL audit event. Everything else that is allowed is a routine read.
var privilegedMethods = map[string]bool{
	"/sentinel.v1.FleetService/Register":        true,
	"/sentinel.v1.FleetService/AcceptPairing":   true,
	"/sentinel.v1.SessionService/Destroy":       true,
	"/sentinel.v1.ExecService/Exec":             true,
	"/sentinel.v1.ExecService/ExecStream":       true,
	"/sentinel.v1.FileSystemService/WriteFile":  true,
	"/sentinel.v1.FileSystemService/Upload":     true,
	"/sentinel.v1.FileSystemService/Delete":     true,
	"/sentinel.v1.SessionService/Create":        true,
	"/sentinel.v1.SessionService/Resume":        true,
	"/sentinel.v1.SessionService/Pause":         true,
	"/sentinel.v1.SessionService/Checkpoint":    true,
	"/sentinel.v1.PayloadService/Send":          true,
	"/sentinel.v1.PayloadService/SendStream":    true,
	"/sentinel.v1.WorkerService/Spawn":          true,
	"/sentinel.v1.WorkerService/Kill":           true,
	"/sentinel.v1.WorkerService/KillAll":        true,
}

// auditEventForMethod returns the audit event type for an RBAC decision.
func auditEventForMethod(method string, allowed bool) string {
	if !allowed {
		return audit.EventRBACDeny
	}
	if privilegedMethods[method] {
		return audit.EventRBACAllowPrivileged
	}
	return audit.EventRBACAllowRead
}

// emitAccessAudit records the RBAC decision and applies the tiered fail-closed
// posture: a write failure on a CRITICAL event (deny or privileged allow) is
// returned so the caller aborts the operation; a routine read failure is
// swallowed (the logger already mirrors it to slog and bumps its metric).
func emitAccessAudit(ctx context.Context, logger audit.Logger, method, role string, allowed bool) error {
	if logger == nil {
		return nil
	}
	evType := auditEventForMethod(method, allowed)
	outcome := audit.OutcomeAllow
	if !allowed {
		outcome = audit.OutcomeDeny
	}
	ev := audit.Event{
		Type:    evType,
		Outcome: outcome,
		Target:  method,
		Detail:  map[string]any{"method": method, "role": role},
	}
	err := logger.Record(ctx, ev)
	if err == nil {
		return nil
	}
	// Routine reads fail open; critical events fail closed. The tier comes from
	// the single exported catalog in internal/audit — no mirrored map here, so a
	// newly-classified event cannot drift out of sync (spec §10 biggest risk).
	if crit, _ := audit.CriticalityOf(evType); crit == audit.Routine {
		return nil
	}
	return fmt.Errorf("audit: refusing to proceed unaudited: %w", err)
}

// deviceIDFromCert derives a stable actor id from the peer certificate: the
// SHA-256 of its raw DER, hex-encoded. This is the anti-forgery actor — it comes
// from the verified mTLS chain, never from the request body.
func deviceIDFromCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// unaryRBACInterceptor returns a gRPC unary server interceptor that enforces
// role-based access control by extracting the client certificate from the TLS
// peer info and checking the embedded role against the policy.
func unaryRBACInterceptor(policy *rbac.Policy, logger audit.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		actorCtx, err := checkAccess(ctx, info.FullMethod, policy, logger)
		if err != nil {
			return nil, err
		}
		return handler(actorCtx, req)
	}
}

// streamRBACInterceptor returns a gRPC stream server interceptor that enforces
// role-based access control by extracting the client certificate from the TLS
// peer info and checking the embedded role against the policy.
func streamRBACInterceptor(policy *rbac.Policy, logger audit.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		actorCtx, err := checkAccess(ss.Context(), info.FullMethod, policy, logger)
		if err != nil {
			return err
		}
		return handler(srv, &auditServerStream{ServerStream: ss, ctx: actorCtx})
	}
}

// auditServerStream overrides Context so the seeded actor reaches the handler.
type auditServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *auditServerStream) Context() context.Context { return s.ctx }

// checkAccess extracts the peer certificate, verifies the role against policy,
// seeds the audit actor, and emits the RBAC decision. The returned context
// carries the actor so downstream handlers' audit records are attributed.
func checkAccess(ctx context.Context, method string, policy *rbac.Policy, logger audit.Logger) (context.Context, error) {
	cert, err := extractPeerCert(ctx)
	if err != nil {
		return ctx, status.Errorf(codes.Unauthenticated, "mtls: %v", err)
	}
	role, err := ca.ExtractRole(cert)
	if err != nil {
		return ctx, status.Errorf(codes.Unauthenticated, "mtls: failed to extract role: %v", err)
	}

	actorCtx := audit.WithActor(ctx, deviceIDFromCert(cert), role)

	if perr := policy.Check(method, role); perr != nil {
		// Denied: emit a critical rbac.deny. If even the audit write fails we
		// still deny (the policy error stands); we just surface the audit failure
		// in the message for the operator.
		if aerr := emitAccessAudit(actorCtx, logger, method, role, false); aerr != nil {
			return actorCtx, status.Errorf(codes.PermissionDenied, "%v (audit: %v)", perr, aerr)
		}
		return actorCtx, status.Errorf(codes.PermissionDenied, "%v", perr)
	}

	// Allowed: emit allow event. A critical allow whose audit write fails must
	// abort the call (fail-closed) so nothing privileged happens un-audited.
	if aerr := emitAccessAudit(actorCtx, logger, method, role, true); aerr != nil {
		return actorCtx, status.Errorf(codes.Unavailable, "audit unavailable: %v", aerr)
	}
	return actorCtx, nil
}

// extractPeerCert retrieves the client's x509 certificate from gRPC peer info.
func extractPeerCert(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer info in context")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("peer auth info is not TLS")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate presented")
	}

	return tlsInfo.State.PeerCertificates[0], nil
}
