package grpc

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/rbac"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// unaryRBACInterceptor returns a gRPC unary server interceptor that enforces
// role-based access control by extracting the client certificate from the TLS
// peer info and checking the embedded role against the policy.
func unaryRBACInterceptor(policy *rbac.Policy) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := checkAccess(ctx, info.FullMethod, policy); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// streamRBACInterceptor returns a gRPC stream server interceptor that enforces
// role-based access control by extracting the client certificate from the TLS
// peer info and checking the embedded role against the policy.
func streamRBACInterceptor(policy *rbac.Policy) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := checkAccess(ss.Context(), info.FullMethod, policy); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// checkAccess extracts the peer certificate and verifies the role against policy.
func checkAccess(ctx context.Context, method string, policy *rbac.Policy) error {
	cert, err := extractPeerCert(ctx)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "mtls: %v", err)
	}

	role, err := ca.ExtractRole(cert)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "mtls: failed to extract role: %v", err)
	}

	if err := policy.Check(method, role); err != nil {
		return status.Errorf(codes.PermissionDenied, "%v", err)
	}

	return nil
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
