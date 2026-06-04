package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/rbac"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestWithMaxRecvMsgSizeAppendsOption(t *testing.T) {
	cfg := &serverConfig{}
	WithMaxRecvMsgSize(1 << 20)(cfg)
	WithMaxConcurrentStreams(128)(cfg)
	if len(cfg.grpcOpts) != 2 {
		t.Fatalf("expected 2 grpc opts, got %d", len(cfg.grpcOpts))
	}
}

func TestRateLimiterHonoursConfiguredRate(t *testing.T) {
	// A 2/sec limiter allows exactly two before refusing.
	rl := NewRateLimiter(2, time.Second)
	if !rl.Allow("c1") {
		t.Fatal("first request for c1 should be allowed")
	}
	if !rl.Allow("c1") {
		t.Fatal("second request for c1 should be allowed")
	}
	if rl.Allow("c1") {
		t.Fatal("third request should be rate-limited")
	}
	// A different client has its own bucket.
	if !rl.Allow("c2") {
		t.Fatal("second client should be allowed")
	}
}

// echoPayload is a minimal PayloadServiceServer used only in the size-cap test.
type echoPayload struct {
	v1.UnimplementedPayloadServiceServer
}

func (e *echoPayload) Send(_ context.Context, req *v1.PayloadRequest) (*v1.PayloadResponse, error) {
	return &v1.PayloadResponse{Payload: req.GetPayload()}, nil
}

func TestMaxRecvMsgSizeRejectsOversized(t *testing.T) {
	// Build a tiny CA and sign server + client certs.
	authority, err := ca.Init(t.TempDir())
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	srvCert, srvKey, err := authority.SignDevice(ca.RoleAdmin)
	if err != nil {
		t.Fatalf("sign server: %v", err)
	}
	caPEM := authority.RootCertPEM()
	cliCert, cliKey, err := authority.SignDevice(ca.RoleOperator)
	if err != nil {
		t.Fatalf("sign client: %v", err)
	}

	// Build a server with a tiny 64-byte recv cap.
	s, err := NewServer(srvCert, srvKey, caPEM, rbac.NewPolicy(), nil,
		WithMaxRecvMsgSize(64))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	v1.RegisterPayloadServiceServer(s.GRPCServer(), &echoPayload{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.GRPCServer().Serve(lis) }()
	defer s.GRPCServer().Stop()

	// Build mTLS client credentials. The CA-signed device certs carry no SANs,
	// so we skip hostname verification and manually confirm CA trust instead —
	// the same approach used by client.Connect.
	clientCert, err := tls.X509KeyPair(cliCert, cliKey)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("append CA cert")
	}
	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caPool,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // hostname not applicable; CA trust verified below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse peer cert: %w", err)
			}
			if _, err := peerCert.Verify(x509.VerifyOptions{Roots: caPool}); err != nil {
				return fmt.Errorf("peer cert not signed by CA: %w", err)
			}
			return nil
		},
	}
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewPayloadServiceClient(conn)
	// Payload string well over the 64-byte cap.
	big := strings.Repeat("x", 1024)
	_, err = client.Send(context.Background(), &v1.PayloadRequest{Payload: big})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized Send: code = %v, want ResourceExhausted (err=%v)", status.Code(err), err)
	}
}
