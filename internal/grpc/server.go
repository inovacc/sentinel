package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/inovacc/sentinel/internal/rbac"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	// TODO: uncomment once proto-generated code exists.
	// v1 "github.com/inovacc/sentinel/internal/api/v1"
)

// Option configures the Server.
type Option func(*serverConfig)

type serverConfig struct {
	extraUnaryInterceptors  []grpc.UnaryServerInterceptor
	extraStreamInterceptors []grpc.StreamServerInterceptor
	grpcOpts                []grpc.ServerOption
}

// WithUnaryInterceptor adds an additional unary interceptor to the chain.
func WithUnaryInterceptor(i grpc.UnaryServerInterceptor) Option {
	return func(c *serverConfig) {
		c.extraUnaryInterceptors = append(c.extraUnaryInterceptors, i)
	}
}

// WithStreamInterceptor adds an additional stream interceptor to the chain.
func WithStreamInterceptor(i grpc.StreamServerInterceptor) Option {
	return func(c *serverConfig) {
		c.extraStreamInterceptors = append(c.extraStreamInterceptors, i)
	}
}

// WithServerOption adds a raw gRPC server option.
func WithServerOption(o grpc.ServerOption) Option {
	return func(c *serverConfig) {
		c.grpcOpts = append(c.grpcOpts, o)
	}
}

// Server wraps a gRPC server with mTLS and interceptors.
type Server struct {
	grpcServer *grpc.Server
	listener   net.Listener
	tlsConfig  *tls.Config
}

// NewServer creates a gRPC server configured with mTLS.
// certPEM/keyPEM are the server's TLS certificate and key.
// caCertPEM is the CA certificate used to verify client certificates.
// The RBAC unary and stream interceptors are registered using the given policy.
func NewServer(certPEM, keyPEM, caCertPEM []byte, policy *rbac.Policy, opts ...Option) (*Server, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("grpc: load server keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("grpc: failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}

	cfg := &serverConfig{}
	for _, o := range opts {
		o(cfg)
	}

	// Build interceptor chains: RBAC first, then any extras.
	unaryChain := append(
		[]grpc.UnaryServerInterceptor{unaryRBACInterceptor(policy)},
		cfg.extraUnaryInterceptors...,
	)
	streamChain := append(
		[]grpc.StreamServerInterceptor{streamRBACInterceptor(policy)},
		cfg.extraStreamInterceptors...,
	)

	grpcOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(unaryChain...),
		grpc.ChainStreamInterceptor(streamChain...),
	}
	grpcOpts = append(grpcOpts, cfg.grpcOpts...)

	return &Server{
		grpcServer: grpc.NewServer(grpcOpts...),
		tlsConfig:  tlsCfg,
	}, nil
}

// GRPCServer returns the underlying *grpc.Server for direct service registration.
// Use this to register proto-generated services until the typed Register methods
// are available.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}

// Serve starts the gRPC server listening on the given address.
func (s *Server) Serve(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc: listen %s: %w", addr, err)
	}
	s.listener = lis
	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}

// --- Service registration stubs ---
// These will be uncommented once proto-generated code is available.

// RegisterExecService registers the ExecService implementation.
// TODO: uncomment once proto-generated code exists.
// func (s *Server) RegisterExecService(svc v1.ExecServiceServer) {
// 	v1.RegisterExecServiceServer(s.grpcServer, svc)
// }

// RegisterFileSystemService registers the FileSystemService implementation.
// TODO: uncomment once proto-generated code exists.
// func (s *Server) RegisterFileSystemService(svc v1.FileSystemServiceServer) {
// 	v1.RegisterFileSystemServiceServer(s.grpcServer, svc)
// }

// RegisterFleetService registers the FleetService implementation.
// TODO: uncomment once proto-generated code exists.
// func (s *Server) RegisterFleetService(svc v1.FleetServiceServer) {
// 	v1.RegisterFleetServiceServer(s.grpcServer, svc)
// }

// RegisterCaptureService registers the CaptureService implementation.
// TODO: uncomment once proto-generated code exists.
// func (s *Server) RegisterCaptureService(svc v1.CaptureServiceServer) {
// 	v1.RegisterCaptureServiceServer(s.grpcServer, svc)
// }

// RegisterSessionService registers the SessionService implementation.
// TODO: uncomment once proto-generated code exists.
// func (s *Server) RegisterSessionService(svc v1.SessionServiceServer) {
// 	v1.RegisterSessionServiceServer(s.grpcServer, svc)
// }
