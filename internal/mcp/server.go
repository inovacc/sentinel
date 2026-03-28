// Package mcp implements the MCP stdio server for Claude Code integration.
package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/exec"
	"github.com/inovacc/sentinel/internal/fleet"
	"github.com/inovacc/sentinel/internal/fs"
	"github.com/inovacc/sentinel/internal/session"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server wraps the MCP server with sentinel tool implementations.
type Server struct {
	mcpServer  *gomcp.Server
	runner     *exec.Runner
	fsSvc      *fs.Service
	sessionMgr *session.Manager
	dbPath     string // for fleet registry lookups
	certDir    string // for loading mTLS certs
}

// NewServer creates an MCP server with all sentinel tools registered.
func NewServer(runner *exec.Runner, fsSvc *fs.Service, sessionMgr *session.Manager, dbPath, certDir string) *Server {
	s := &Server{
		runner:     runner,
		fsSvc:      fsSvc,
		sessionMgr: sessionMgr,
		dbPath:     dbPath,
		certDir:    certDir,
	}

	s.mcpServer = gomcp.NewServer(
		&gomcp.Implementation{
			Name:    "sentinel",
			Version: "0.1.0",
		},
		&gomcp.ServerOptions{},
	)

	s.registerTools()
	return s
}

// Run starts the MCP server on stdio transport (blocks).
func (s *Server) Run(ctx context.Context) error {
	return s.mcpServer.Run(ctx, &gomcp.StdioTransport{})
}

func (s *Server) registerTools() {
	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "exec",
		Description: "Execute a command on the remote machine within the sandbox",
	}, s.handleExec)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "read_file",
		Description: "Read a file from the sandbox or allowlisted paths",
	}, s.handleReadFile)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "write_file",
		Description: "Write a file to the sandbox directory",
	}, s.handleWriteFile)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "list_dir",
		Description: "List directory contents within sandbox or allowlisted paths",
	}, s.handleListDir)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "glob",
		Description: "Find files matching a glob pattern within allowed paths",
	}, s.handleGlob)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "grep",
		Description: "Search file contents using regex within allowed paths",
	}, s.handleGrep)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "delete_file",
		Description: "Delete a file within the sandbox directory",
	}, s.handleDeleteFile)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "session_create",
		Description: "Create a new session on a device for tracking work state",
	}, s.handleSessionCreate)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "session_list",
		Description: "List all sessions, optionally filtered by status or device",
	}, s.handleSessionList)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "session_resume",
		Description: "Resume an interrupted or paused session, returning its full state",
	}, s.handleSessionResume)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "session_pause",
		Description: "Pause an active session, saving a checkpoint",
	}, s.handleSessionPause)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "session_status",
		Description: "Get detailed status of a session",
	}, s.handleSessionStatus)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "session_destroy",
		Description: "End and clean up a session",
	}, s.handleSessionDestroy)
}

// --- Input types ---

type ExecInput struct {
	DeviceID   string            `json:"device_id,omitempty" jsonschema:"target device ID (empty = local)"`
	Command    string            `json:"command" jsonschema:"the command to execute"`
	Args       []string          `json:"args,omitempty" jsonschema:"command arguments"`
	WorkingDir string            `json:"working_dir,omitempty" jsonschema:"working directory relative to sandbox"`
	Env        map[string]string `json:"env,omitempty" jsonschema:"environment variables"`
	Timeout    int               `json:"timeout,omitempty" jsonschema:"timeout in seconds (default 30)"`
}

type ReadFileInput struct {
	DeviceID string `json:"device_id,omitempty" jsonschema:"target device ID (empty = local)"`
	Path     string `json:"path" jsonschema:"file path to read"`
	Offset   int64  `json:"offset,omitempty" jsonschema:"byte offset to start reading from"`
	Limit    int64  `json:"limit,omitempty" jsonschema:"max bytes to read (0 = all)"`
}

type WriteFileInput struct {
	DeviceID   string `json:"device_id,omitempty" jsonschema:"target device ID (empty = local)"`
	Path       string `json:"path" jsonschema:"file path to write (within sandbox)"`
	Content    string `json:"content" jsonschema:"file content to write"`
	CreateDirs bool   `json:"create_dirs,omitempty" jsonschema:"create parent directories if needed"`
}

type ListDirInput struct {
	DeviceID  string `json:"device_id,omitempty" jsonschema:"target device ID (empty = local)"`
	Path      string `json:"path" jsonschema:"directory path to list"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"list recursively"`
}

type GlobInput struct {
	DeviceID string `json:"device_id,omitempty" jsonschema:"target device ID (empty = local)"`
	Pattern  string `json:"pattern" jsonschema:"glob pattern to match"`
	BasePath string `json:"base_path,omitempty" jsonschema:"base directory for matching"`
}

type GrepInput struct {
	DeviceID     string `json:"device_id,omitempty" jsonschema:"target device ID (empty = local)"`
	Pattern      string `json:"pattern" jsonschema:"regex pattern to search for"`
	Path         string `json:"path" jsonschema:"file or directory to search"`
	Recursive    bool   `json:"recursive,omitempty" jsonschema:"search directories recursively"`
	IgnoreCase   bool   `json:"ignore_case,omitempty" jsonschema:"case insensitive search"`
	ContextLines int    `json:"context_lines,omitempty" jsonschema:"lines of context around matches"`
}

type DeleteFileInput struct {
	DeviceID string `json:"device_id,omitempty" jsonschema:"target device ID (empty = local)"`
	Path     string `json:"path" jsonschema:"file path to delete (within sandbox only)"`
}

type SessionCreateInput struct {
	DeviceID    string            `json:"device_id,omitempty" jsonschema:"target device ID"`
	ProjectName string            `json:"project_name" jsonschema:"name of the project"`
	Description string            `json:"description,omitempty" jsonschema:"session description"`
	WorkingDir  string            `json:"working_dir,omitempty" jsonschema:"initial working directory"`
	Env         map[string]string `json:"env,omitempty" jsonschema:"initial environment variables"`
}

type SessionListInput struct {
	DeviceID     string `json:"device_id,omitempty" jsonschema:"filter by device ID"`
	StatusFilter string `json:"status,omitempty" jsonschema:"filter by status"`
	Limit        int    `json:"limit,omitempty" jsonschema:"max results (default 50)"`
}

type SessionIDInput struct {
	SessionID string `json:"session_id" jsonschema:"ID of the session"`
}

type SessionPauseInput struct {
	SessionID string `json:"session_id" jsonschema:"ID of the session to pause"`
	Reason    string `json:"reason,omitempty" jsonschema:"reason for pausing"`
}

// --- Handlers ---

// isLocal returns true if the device ID indicates local execution.
func isLocal(deviceID string) bool {
	return deviceID == "" || strings.EqualFold(deviceID, "local")
}

func (s *Server) handleExec(_ context.Context, _ *gomcp.CallToolRequest, input ExecInput) (*gomcp.CallToolResult, any, error) {
	ctx := context.Background()

	if !isLocal(input.DeviceID) {
		result, err := s.remoteExec(input.DeviceID, input.Command, input.Args, input.WorkingDir, input.Timeout)
		if err != nil {
			return errResult(err), nil, nil
		}
		return formatExecResult(result), nil, nil
	}

	req := &exec.RunRequest{
		Command:    input.Command,
		Args:       input.Args,
		WorkingDir: input.WorkingDir,
		Env:        input.Env,
	}
	if input.Timeout > 0 {
		req.Timeout = time.Duration(input.Timeout) * time.Second
	}

	result, err := s.runner.Run(ctx, req)
	if err != nil {
		return errResult(err), nil, nil
	}

	return formatExecResult(result), nil, nil
}

func formatExecResult(result *exec.RunResult) *gomcp.CallToolResult {
	output := fmt.Sprintf("Exit code: %d\nDuration: %dms\n\n--- stdout ---\n%s", result.ExitCode, result.DurationMs, result.Stdout)
	if result.Stderr != "" {
		output += fmt.Sprintf("\n--- stderr ---\n%s", result.Stderr)
	}
	return txtResult(output)
}

func (s *Server) handleReadFile(_ context.Context, _ *gomcp.CallToolRequest, input ReadFileInput) (*gomcp.CallToolResult, any, error) {
	if !isLocal(input.DeviceID) {
		content, err := s.remoteReadFile(input.DeviceID, input.Path, input.Offset, input.Limit)
		if err != nil {
			return errResult(err), nil, nil
		}
		return txtResult(string(content)), nil, nil
	}

	content, _, _, err := s.fsSvc.ReadFile(input.Path, input.Offset, input.Limit)
	if err != nil {
		return errResult(err), nil, nil
	}
	return txtResult(string(content)), nil, nil
}

func (s *Server) handleWriteFile(_ context.Context, _ *gomcp.CallToolRequest, input WriteFileInput) (*gomcp.CallToolResult, any, error) {
	if !isLocal(input.DeviceID) {
		written, err := s.remoteWriteFile(input.DeviceID, input.Path, []byte(input.Content), input.CreateDirs)
		if err != nil {
			return errResult(err), nil, nil
		}
		return txtResult(fmt.Sprintf("Written %d bytes to %s (device: %s)", written, input.Path, input.DeviceID)), nil, nil
	}

	written, err := s.fsSvc.WriteFile(input.Path, []byte(input.Content), input.CreateDirs)
	if err != nil {
		return errResult(err), nil, nil
	}
	return txtResult(fmt.Sprintf("Written %d bytes to %s", written, input.Path)), nil, nil
}

func (s *Server) handleListDir(_ context.Context, _ *gomcp.CallToolRequest, input ListDirInput) (*gomcp.CallToolResult, any, error) {
	if !isLocal(input.DeviceID) {
		entries, err := s.remoteListDir(input.DeviceID, input.Path, input.Recursive)
		if err != nil {
			return errResult(err), nil, nil
		}
		data, _ := json.MarshalIndent(entries, "", "  ")
		return txtResult(string(data)), nil, nil
	}

	entries, err := s.fsSvc.ListDir(input.Path, input.Recursive)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, _ := json.MarshalIndent(entries, "", "  ")
	return txtResult(string(data)), nil, nil
}

func (s *Server) handleGlob(_ context.Context, _ *gomcp.CallToolRequest, input GlobInput) (*gomcp.CallToolResult, any, error) {
	if !isLocal(input.DeviceID) {
		matches, err := s.remoteGlob(input.DeviceID, input.Pattern, input.BasePath)
		if err != nil {
			return errResult(err), nil, nil
		}
		data, _ := json.MarshalIndent(matches, "", "  ")
		return txtResult(string(data)), nil, nil
	}

	matches, err := s.fsSvc.Glob(input.Pattern, input.BasePath)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, _ := json.MarshalIndent(matches, "", "  ")
	return txtResult(string(data)), nil, nil
}

func (s *Server) handleGrep(_ context.Context, _ *gomcp.CallToolRequest, input GrepInput) (*gomcp.CallToolResult, any, error) {
	if !isLocal(input.DeviceID) {
		matches, err := s.remoteGrep(input.DeviceID, input.Pattern, input.Path, input.Recursive, input.IgnoreCase, input.ContextLines)
		if err != nil {
			return errResult(err), nil, nil
		}
		data, _ := json.MarshalIndent(matches, "", "  ")
		return txtResult(string(data)), nil, nil
	}

	matches, err := s.fsSvc.Grep(input.Pattern, input.Path, input.Recursive, input.IgnoreCase, input.ContextLines)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, _ := json.MarshalIndent(matches, "", "  ")
	return txtResult(string(data)), nil, nil
}

func (s *Server) handleDeleteFile(_ context.Context, _ *gomcp.CallToolRequest, input DeleteFileInput) (*gomcp.CallToolResult, any, error) {
	if !isLocal(input.DeviceID) {
		if err := s.remoteDeleteFile(input.DeviceID, input.Path); err != nil {
			return errResult(err), nil, nil
		}
		return txtResult(fmt.Sprintf("Deleted %s (device: %s)", input.Path, input.DeviceID)), nil, nil
	}

	if err := s.fsSvc.DeleteFile(input.Path); err != nil {
		return errResult(err), nil, nil
	}
	return txtResult(fmt.Sprintf("Deleted %s", input.Path)), nil, nil
}

func (s *Server) handleSessionCreate(_ context.Context, _ *gomcp.CallToolRequest, input SessionCreateInput) (*gomcp.CallToolResult, any, error) {
	ctx := context.Background()
	sess, err := s.sessionMgr.Create(ctx, input.DeviceID, input.ProjectName, input.Description, input.WorkingDir, input.Env)
	if err != nil {
		return errResult(err), nil, nil
	}
	return txtResult(fmt.Sprintf("Session created: %s (device: %s)", sess.ID, sess.DeviceID)), nil, nil
}

func (s *Server) handleSessionList(_ context.Context, _ *gomcp.CallToolRequest, input SessionListInput) (*gomcp.CallToolResult, any, error) {
	ctx := context.Background()
	limit := input.Limit
	if limit == 0 {
		limit = 50
	}
	sessions, err := s.sessionMgr.List(ctx, input.DeviceID, session.Status(input.StatusFilter), limit)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, _ := json.MarshalIndent(sessions, "", "  ")
	return txtResult(string(data)), nil, nil
}

func (s *Server) handleSessionResume(_ context.Context, _ *gomcp.CallToolRequest, input SessionIDInput) (*gomcp.CallToolResult, any, error) {
	ctx := context.Background()
	sess, checkpoint, events, err := s.sessionMgr.Resume(ctx, input.SessionID)
	if err != nil {
		return errResult(err), nil, nil
	}

	info := map[string]any{
		"session_id":         sess.ID,
		"status":             string(sess.Status),
		"context":            sess.Context,
		"error":              sess.ErrorInfo,
		"last_checkpoint":    checkpoint,
		"recent_event_count": len(events),
	}
	data, _ := json.MarshalIndent(info, "", "  ")
	return txtResult(string(data)), nil, nil
}

func (s *Server) handleSessionPause(_ context.Context, _ *gomcp.CallToolRequest, input SessionPauseInput) (*gomcp.CallToolResult, any, error) {
	ctx := context.Background()
	cp, err := s.sessionMgr.Pause(ctx, input.SessionID, input.Reason)
	if err != nil {
		return errResult(err), nil, nil
	}
	return txtResult(fmt.Sprintf("Session paused. Checkpoint: %d", cp.ID)), nil, nil
}

func (s *Server) handleSessionStatus(_ context.Context, _ *gomcp.CallToolRequest, input SessionIDInput) (*gomcp.CallToolResult, any, error) {
	ctx := context.Background()
	sess, err := s.sessionMgr.Get(ctx, input.SessionID)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, _ := json.MarshalIndent(sess, "", "  ")
	return txtResult(string(data)), nil, nil
}

func (s *Server) handleSessionDestroy(_ context.Context, _ *gomcp.CallToolRequest, input SessionIDInput) (*gomcp.CallToolResult, any, error) {
	ctx := context.Background()
	if err := s.sessionMgr.Destroy(ctx, input.SessionID); err != nil {
		return errResult(err), nil, nil
	}
	return txtResult(fmt.Sprintf("Session %s destroyed", input.SessionID)), nil, nil
}

// --- remote routing helpers ---

// resolveDevice looks up a device in the fleet registry and returns its address.
func (s *Server) resolveDevice(deviceID string) (string, error) {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return "", fmt.Errorf("open fleet db: %w", err)
	}
	defer func() { _ = db.Close() }()

	registry, err := fleet.NewRegistry(db)
	if err != nil {
		return "", fmt.Errorf("init fleet registry: %w", err)
	}

	device, err := registry.Get(deviceID)
	if err != nil {
		return "", fmt.Errorf("device %q not found: %w", deviceID, err)
	}
	if device.Address == "" {
		return "", fmt.Errorf("device %q has no address configured", deviceID)
	}
	return device.Address, nil
}

// dialDevice creates a gRPC connection to a remote device using mTLS.
func (s *Server) dialDevice(deviceID string) (*grpc.ClientConn, error) {
	addr, err := s.resolveDevice(deviceID)
	if err != nil {
		return nil, err
	}

	certPEM, err := os.ReadFile(filepath.Join(s.certDir, "device.crt"))
	if err != nil {
		return nil, fmt.Errorf("read client cert: %w", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(s.certDir, "device.key"))
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(s.certDir, "..", "ca", "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("dial device %q at %s: %w", deviceID, addr, err)
	}
	return conn, nil
}

// remoteExec executes a command on a remote device via gRPC.
func (s *Server) remoteExec(deviceID string, command string, args []string, workingDir string, timeout int) (*exec.RunResult, error) {
	conn, err := s.dialDevice(deviceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewExecServiceClient(conn)
	req := &v1.ExecRequest{
		Command:    command,
		Args:       args,
		WorkingDir: workingDir,
	}
	if timeout > 0 {
		req.TimeoutSeconds = int32(timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+10)*time.Second)
	defer cancel()

	resp, err := client.Exec(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("remote exec on %q: %w", deviceID, err)
	}

	return &exec.RunResult{
		ExitCode:   int(resp.ExitCode),
		Stdout:     resp.Stdout,
		Stderr:     resp.Stderr,
		DurationMs: resp.DurationMs,
	}, nil
}

// remoteReadFile reads a file from a remote device.
func (s *Server) remoteReadFile(deviceID, path string, offset, limit int64) ([]byte, error) {
	conn, err := s.dialDevice(deviceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewFileSystemServiceClient(conn)
	resp, err := client.ReadFile(context.Background(), &v1.ReadFileRequest{
		Path:   path,
		Offset: offset,
		Limit:  limit,
	})
	if err != nil {
		return nil, fmt.Errorf("remote read_file on %q: %w", deviceID, err)
	}
	return resp.Content, nil
}

// remoteWriteFile writes a file on a remote device.
func (s *Server) remoteWriteFile(deviceID, path string, content []byte, createDirs bool) (int64, error) {
	conn, err := s.dialDevice(deviceID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewFileSystemServiceClient(conn)
	resp, err := client.WriteFile(context.Background(), &v1.WriteFileRequest{
		Path:       path,
		Content:    content,
		CreateDirs: createDirs,
	})
	if err != nil {
		return 0, fmt.Errorf("remote write_file on %q: %w", deviceID, err)
	}
	return resp.BytesWritten, nil
}

// remoteListDir lists a directory on a remote device.
func (s *Server) remoteListDir(deviceID, path string, recursive bool) ([]*v1.FileEntry, error) {
	conn, err := s.dialDevice(deviceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewFileSystemServiceClient(conn)
	resp, err := client.ListDir(context.Background(), &v1.ListDirRequest{
		Path:      path,
		Recursive: recursive,
	})
	if err != nil {
		return nil, fmt.Errorf("remote list_dir on %q: %w", deviceID, err)
	}
	return resp.Entries, nil
}

// remoteGlob runs a glob pattern match on a remote device.
func (s *Server) remoteGlob(deviceID, pattern, basePath string) ([]string, error) {
	conn, err := s.dialDevice(deviceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewFileSystemServiceClient(conn)
	resp, err := client.Glob(context.Background(), &v1.GlobRequest{
		Pattern:  pattern,
		BasePath: basePath,
	})
	if err != nil {
		return nil, fmt.Errorf("remote glob on %q: %w", deviceID, err)
	}
	return resp.Matches, nil
}

// remoteGrep searches file contents on a remote device.
func (s *Server) remoteGrep(deviceID, pattern, path string, recursive, ignoreCase bool, contextLines int) ([]*v1.GrepMatch, error) {
	conn, err := s.dialDevice(deviceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewFileSystemServiceClient(conn)
	resp, err := client.Grep(context.Background(), &v1.GrepRequest{
		Pattern:      pattern,
		Path:         path,
		Recursive:    recursive,
		IgnoreCase:   ignoreCase,
		ContextLines: int32(contextLines),
	})
	if err != nil {
		return nil, fmt.Errorf("remote grep on %q: %w", deviceID, err)
	}
	return resp.Matches, nil
}

// remoteDeleteFile deletes a file on a remote device.
func (s *Server) remoteDeleteFile(deviceID, path string) error {
	conn, err := s.dialDevice(deviceID)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewFileSystemServiceClient(conn)
	_, err = client.Delete(context.Background(), &v1.DeleteRequest{
		Path: path,
	})
	if err != nil {
		return fmt.Errorf("remote delete_file on %q: %w", deviceID, err)
	}
	return nil
}

// --- helpers ---

func txtResult(text string) *gomcp.CallToolResult {
	return &gomcp.CallToolResult{
		Content: []gomcp.Content{&gomcp.TextContent{Text: text}},
	}
}

func errResult(err error) *gomcp.CallToolResult {
	r := &gomcp.CallToolResult{}
	r.SetError(err)
	return r
}
