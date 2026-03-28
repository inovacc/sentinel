// Package client provides a gRPC client for connecting to remote sentinel daemons.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/pkg/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// uploadChunkSize is the size of each chunk sent during Upload (32KB).
	uploadChunkSize = 32 * 1024
)

// Client connects to a remote sentinel daemon via gRPC/mTLS.
type Client struct {
	conn *grpc.ClientConn
	exec v1.ExecServiceClient
	fs   v1.FileSystemServiceClient
	sess v1.SessionServiceClient
}

// Connect dials the remote sentinel at addr using mTLS credentials.
func Connect(addr string, certPEM, keyPEM, caCertPEM []byte) (*Client, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("client: load keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("client: failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Skip hostname/IP SAN check.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// Manually verify the peer cert is signed by our CA.
			if len(rawCerts) == 0 {
				return fmt.Errorf("client: no peer certificate")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("client: parse peer cert: %w", err)
			}
			_, err = peerCert.Verify(x509.VerifyOptions{Roots: caPool})
			if err != nil {
				return fmt.Errorf("client: peer cert not signed by CA: %w", err)
			}
			return nil
		},
	}

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("client: dial %s: %w", addr, err)
	}

	return &Client{
		conn: conn,
		exec: v1.NewExecServiceClient(conn),
		fs:   v1.NewFileSystemServiceClient(conn),
		sess: v1.NewSessionServiceClient(conn),
	}, nil
}

// ConnectFromStore loads mTLS certificates from a CertStore directory and connects.
func ConnectFromStore(addr string, certDir string) (*Client, error) {
	store, err := transport.NewCertStore(certDir)
	if err != nil {
		return nil, fmt.Errorf("client: open cert store: %w", err)
	}

	if !store.HasMTLS() {
		return nil, fmt.Errorf("client: no mTLS certificates found in %s (run 'sentinel pair' first)", certDir)
	}

	certPEM, keyPEM, caCertPEM, err := store.LoadMTLS()
	if err != nil {
		return nil, fmt.Errorf("client: load mTLS certs: %w", err)
	}

	return Connect(addr, certPEM, keyPEM, caCertPEM)
}

// Exec executes a command on the remote device and returns the full response.
func (c *Client) Exec(ctx context.Context, command string, args []string, workingDir string, timeout int32) (*v1.ExecResponse, error) {
	req := &v1.ExecRequest{
		Command:        command,
		Args:           args,
		WorkingDir:     workingDir,
		TimeoutSeconds: timeout,
	}

	resp, err := c.exec.Exec(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("client: exec: %w", err)
	}
	return resp, nil
}

// ExecStream executes a command with streaming output. The onOutput callback is
// called for each chunk of output with the stream name ("stdout" or "stderr")
// and data bytes. Returns the exit code.
func (c *Client) ExecStream(ctx context.Context, command string, args []string, workingDir string, timeout int32, onOutput func(stream string, data []byte)) (int32, error) {
	req := &v1.ExecRequest{
		Command:        command,
		Args:           args,
		WorkingDir:     workingDir,
		TimeoutSeconds: timeout,
	}

	stream, err := c.exec.ExecStream(ctx, req)
	if err != nil {
		return -1, fmt.Errorf("client: exec stream: %w", err)
	}

	var exitCode int32
	for {
		out, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return -1, fmt.Errorf("client: recv stream: %w", err)
		}

		if onOutput != nil && len(out.GetData()) > 0 {
			streamName := "stdout"
			if out.GetStream() == v1.ExecOutput_STDERR {
				streamName = "stderr"
			}
			onOutput(streamName, out.GetData())
		}

		if out.GetDone() {
			exitCode = out.GetExitCode()
			break
		}
	}

	return exitCode, nil
}

// ReadFile reads a file from the remote device.
func (c *Client) ReadFile(ctx context.Context, path string) ([]byte, error) {
	resp, err := c.fs.ReadFile(ctx, &v1.ReadFileRequest{Path: path})
	if err != nil {
		return nil, fmt.Errorf("client: read file: %w", err)
	}
	return resp.GetContent(), nil
}

// WriteFile writes content to a file on the remote device.
func (c *Client) WriteFile(ctx context.Context, path string, content []byte) error {
	_, err := c.fs.WriteFile(ctx, &v1.WriteFileRequest{
		Path:       path,
		Content:    content,
		CreateDirs: true,
	})
	if err != nil {
		return fmt.Errorf("client: write file: %w", err)
	}
	return nil
}

// ListDir lists directory contents on the remote device.
func (c *Client) ListDir(ctx context.Context, path string, recursive bool) ([]*v1.FileEntry, error) {
	resp, err := c.fs.ListDir(ctx, &v1.ListDirRequest{
		Path:      path,
		Recursive: recursive,
	})
	if err != nil {
		return nil, fmt.Errorf("client: list dir: %w", err)
	}
	return resp.GetEntries(), nil
}

// Upload sends file data to the remote device in 32KB chunks via streaming.
func (c *Client) Upload(ctx context.Context, targetPath string, data []byte) error {
	stream, err := c.fs.Upload(ctx)
	if err != nil {
		return fmt.Errorf("client: open upload stream: %w", err)
	}

	for offset := 0; offset < len(data); offset += uploadChunkSize {
		end := offset + uploadChunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := &v1.UploadChunk{
			TargetPath: targetPath,
			Data:       data[offset:end],
			IsLast:     end >= len(data),
		}

		if err := stream.Send(chunk); err != nil {
			return fmt.Errorf("client: send chunk: %w", err)
		}
	}

	// Handle empty data (send a single empty chunk marked as last).
	if len(data) == 0 {
		chunk := &v1.UploadChunk{
			TargetPath: targetPath,
			Data:       nil,
			IsLast:     true,
		}
		if err := stream.Send(chunk); err != nil {
			return fmt.Errorf("client: send chunk: %w", err)
		}
	}

	_, err = stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("client: close upload: %w", err)
	}

	return nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
