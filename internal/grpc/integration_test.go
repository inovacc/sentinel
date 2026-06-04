package grpc

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/client"
	"github.com/inovacc/sentinel/internal/exec"
	"github.com/inovacc/sentinel/internal/rbac"
	"github.com/inovacc/sentinel/internal/sandbox"
	"github.com/inovacc/sentinel/internal/worker"
	_ "modernc.org/sqlite"
)

// startTestServer brings up a real mTLS gRPC server with the ExecService
// registered, and returns its address plus a client identity carrying the given
// role. Server and client certs are signed by the same throwaway CA.
func startTestServer(t *testing.T, clientRole string) (addr string, cliCert, cliKey, caPEM []byte) {
	t.Helper()
	authority, err := ca.Init(t.TempDir())
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	srvCert, srvKey, err := authority.SignDevice(ca.RoleAdmin)
	if err != nil {
		t.Fatalf("sign server: %v", err)
	}
	caPEM = authority.RootCertPEM()
	cliCert, cliKey, err = authority.SignDevice(clientRole)
	if err != nil {
		t.Fatalf("sign client: %v", err)
	}

	srv, err := NewServer(srvCert, srvKey, caPEM, rbac.NewPolicy(), nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	sb, err := sandbox.New(sandbox.Config{Root: t.TempDir(), ExecAllowlist: []string{"go"}})
	if err != nil {
		t.Fatalf("sandbox.New: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv.RegisterExecService(NewExecService(exec.NewRunner(sb), nil, logger))

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pool, err := worker.NewPool(db, sb, worker.WithLogger(logger))
	if err != nil {
		t.Fatalf("worker.NewPool: %v", err)
	}
	t.Cleanup(pool.Stop)
	srv.RegisterWorkerService(NewWorkerService(pool))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.ServeListener(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), cliCert, cliKey, caPEM
}

func TestExecOverMTLS_OperatorAllowed(t *testing.T) {
	addr, cert, key, caPEM := startTestServer(t, ca.RoleOperator)
	c, err := client.Connect(addr, cert, key, caPEM)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := c.Exec(ctx, "go", []string{"version"}, "", 15)
	if err != nil {
		t.Fatalf("Exec over mTLS: %v", err)
	}
	if resp.GetExitCode() != 0 {
		t.Errorf("exit = %d, want 0 (stderr=%s)", resp.GetExitCode(), resp.GetStderr())
	}
	if !strings.Contains(resp.GetStdout(), "go version") {
		t.Errorf("stdout = %q, want to contain 'go version'", resp.GetStdout())
	}
}

// TestExecOverMTLS_ReaderDenied is the end-to-end proof that the RBAC interceptor
// enforces method-level roles on the wire: a reader cannot call the
// operator-gated ExecService/Exec.
func TestExecOverMTLS_ReaderDenied(t *testing.T) {
	addr, cert, key, caPEM := startTestServer(t, ca.RoleReader)
	c, err := client.Connect(addr, cert, key, caPEM)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Exec(ctx, "go", []string{"version"}, "", 5); err == nil {
		t.Fatal("a reader role must be denied the operator-gated ExecService/Exec")
	}
}

// TestExecOverMTLS_BlockedCommandRejected confirms the sandbox allowlist is
// enforced through the full RPC path (operator is allowed by RBAC, but the
// command is not allowlisted).
func TestExecOverMTLS_NonAllowlistedRejected(t *testing.T) {
	addr, cert, key, caPEM := startTestServer(t, ca.RoleOperator)
	c, err := client.Connect(addr, cert, key, caPEM)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Exec(ctx, "not-allowlisted", nil, "", 5); err == nil {
		t.Fatal("a non-allowlisted command must be rejected by the sandbox over the wire")
	}
}

// TestWorkerOverMTLS exercises the WorkerService RPC path end-to-end: spawn a
// worker, then list workers and confirm it is tracked.
func TestWorkerOverMTLS(t *testing.T) {
	addr, cert, key, caPEM := startTestServer(t, ca.RoleOperator)
	c, err := client.Connect(addr, cert, key, caPEM)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	spawned, err := c.SpawnWorker(ctx, "go", []string{"version"}, "", nil, "", nil, 15)
	if err != nil {
		t.Fatalf("SpawnWorker: %v", err)
	}
	if spawned.GetWorkerId() == "" {
		t.Fatal("spawned worker has no id")
	}
	listed, err := c.ListWorkers(ctx, "")
	if err != nil {
		t.Fatalf("ListWorkers: %v", err)
	}
	if len(listed.GetWorkers()) == 0 {
		t.Error("ListWorkers returned no workers after a spawn")
	}
}
