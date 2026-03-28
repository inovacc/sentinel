package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/rbac"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// peerCtx creates a context with mock TLS peer info containing the given cert.
func peerCtx(t *testing.T, cert *x509.Certificate) context.Context {
	t.Helper()
	p := &peer.Peer{
		Addr: &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	}
	return peer.NewContext(context.Background(), p)
}

// peerCtxNoCert creates a context with TLS peer info but no client certificate.
func peerCtxNoCert(t *testing.T) context.Context {
	t.Helper()
	p := &peer.Peer{
		Addr: &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{},
			},
		},
	}
	return peer.NewContext(context.Background(), p)
}

// signDeviceCert creates a temporary CA and signs a device cert with the given role.
func signDeviceCert(t *testing.T, role string) *x509.Certificate {
	t.Helper()
	dir := t.TempDir()
	authority, err := ca.Init(dir)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	certPEM, _, err := authority.SignDevice(role)
	if err != nil {
		t.Fatalf("SignDevice(%s): %v", role, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// okHandler is a simple unary handler that returns "ok".
func okHandler(_ context.Context, _ any) (any, error) {
	return "ok", nil
}

func TestUnaryRBACInterceptor_AdminCanAccessAdminMethods(t *testing.T) {
	policy := rbac.NewPolicy()
	interceptor := unaryRBACInterceptor(policy)
	cert := signDeviceCert(t, "admin")
	ctx := peerCtx(t, cert)

	methods := []string{
		"/sentinel.v1.FleetService/Register",
		"/sentinel.v1.FleetService/AcceptPairing",
		"/sentinel.v1.SessionService/Destroy",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			info := &grpc.UnaryServerInfo{FullMethod: method}
			resp, err := interceptor(ctx, nil, info, okHandler)
			if err != nil {
				t.Fatalf("admin should access %s, got: %v", method, err)
			}
			if resp != "ok" {
				t.Fatalf("expected ok, got %v", resp)
			}
		})
	}
}

func TestUnaryRBACInterceptor_ReaderDeniedOperatorMethods(t *testing.T) {
	policy := rbac.NewPolicy()
	interceptor := unaryRBACInterceptor(policy)
	cert := signDeviceCert(t, "reader")
	ctx := peerCtx(t, cert)

	methods := []string{
		"/sentinel.v1.ExecService/Exec",
		"/sentinel.v1.FileSystemService/WriteFile",
		"/sentinel.v1.SessionService/Create",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			info := &grpc.UnaryServerInfo{FullMethod: method}
			_, err := interceptor(ctx, nil, info, okHandler)
			if err == nil {
				t.Fatalf("reader should be denied access to %s", method)
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got: %v", err)
			}
			if st.Code() != codes.PermissionDenied {
				t.Fatalf("expected PermissionDenied, got %v", st.Code())
			}
		})
	}
}

func TestUnaryRBACInterceptor_NoCertRejected(t *testing.T) {
	policy := rbac.NewPolicy()
	interceptor := unaryRBACInterceptor(policy)
	ctx := peerCtxNoCert(t)

	info := &grpc.UnaryServerInfo{FullMethod: "/sentinel.v1.FleetService/Health"}
	_, err := interceptor(ctx, nil, info, okHandler)
	if err == nil {
		t.Fatal("expected error for missing cert")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", st.Code())
	}
}

func TestUnaryRBACInterceptor_NoPeerRejected(t *testing.T) {
	policy := rbac.NewPolicy()
	interceptor := unaryRBACInterceptor(policy)
	ctx := context.Background() // no peer info

	info := &grpc.UnaryServerInfo{FullMethod: "/sentinel.v1.FleetService/Health"}
	_, err := interceptor(ctx, nil, info, okHandler)
	if err == nil {
		t.Fatal("expected error for no peer")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", st.Code())
	}
}

func TestUnaryRBACInterceptor_CertMissingRoleExtension(t *testing.T) {
	policy := rbac.NewPolicy()
	interceptor := unaryRBACInterceptor(policy)

	// Bare certificate with no extensions.
	cert := &x509.Certificate{}
	ctx := peerCtx(t, cert)

	info := &grpc.UnaryServerInfo{FullMethod: "/sentinel.v1.FleetService/Health"}
	_, err := interceptor(ctx, nil, info, okHandler)
	if err == nil {
		t.Fatal("expected error for cert without role extension")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", st.Code())
	}
}

func TestUnaryRBACInterceptor_OperatorCanAccessReaderMethods(t *testing.T) {
	policy := rbac.NewPolicy()
	interceptor := unaryRBACInterceptor(policy)
	cert := signDeviceCert(t, "operator")
	ctx := peerCtx(t, cert)

	methods := []string{
		"/sentinel.v1.FileSystemService/ReadFile",
		"/sentinel.v1.FleetService/ListDevices",
		"/sentinel.v1.FleetService/Health",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			info := &grpc.UnaryServerInfo{FullMethod: method}
			resp, err := interceptor(ctx, nil, info, okHandler)
			if err != nil {
				t.Fatalf("operator should access %s, got: %v", method, err)
			}
			if resp != "ok" {
				t.Fatalf("expected ok, got %v", resp)
			}
		})
	}
}

func TestUnaryRBACInterceptor_OperatorDeniedAdminMethods(t *testing.T) {
	policy := rbac.NewPolicy()
	interceptor := unaryRBACInterceptor(policy)
	cert := signDeviceCert(t, "operator")
	ctx := peerCtx(t, cert)

	methods := []string{
		"/sentinel.v1.FleetService/Register",
		"/sentinel.v1.FleetService/AcceptPairing",
		"/sentinel.v1.SessionService/Destroy",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			info := &grpc.UnaryServerInfo{FullMethod: method}
			_, err := interceptor(ctx, nil, info, okHandler)
			if err == nil {
				t.Fatalf("operator should be denied access to %s", method)
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got: %v", err)
			}
			if st.Code() != codes.PermissionDenied {
				t.Fatalf("expected PermissionDenied, got %v", st.Code())
			}
		})
	}
}
