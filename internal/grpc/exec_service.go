package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/exec"
	"github.com/inovacc/sentinel/internal/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ v1.ExecServiceServer = (*ExecServiceImpl)(nil)

// ExecServiceImpl implements the ExecService gRPC service.
type ExecServiceImpl struct {
	v1.UnimplementedExecServiceServer
	runner     *exec.Runner
	sessionMgr *session.Manager // optional, may be nil
	logger     *slog.Logger
}

// NewExecService creates an ExecService backed by the given runner.
// sessionMgr is optional; when non-nil, exec calls with a session_id will
// automatically create checkpoints before execution and record events after.
// logger may be nil, in which case slog.Default() is used; it records failures
// to persist session audit events so they are never silently dropped.
func NewExecService(runner *exec.Runner, sessionMgr *session.Manager, logger *slog.Logger) *ExecServiceImpl {
	if logger == nil {
		logger = slog.Default()
	}
	return &ExecServiceImpl{runner: runner, sessionMgr: sessionMgr, logger: logger}
}

// Exec executes a command and returns the result.
func (s *ExecServiceImpl) Exec(ctx context.Context, req *v1.ExecRequest) (*v1.ExecResponse, error) {
	sessionID := req.GetSessionId()

	// Pre-exec checkpoint.
	if sessionID != "" && s.sessionMgr != nil {
		cmdDesc := formatCommandDesc(req.GetCommand(), req.GetArgs())
		_, cpErr := s.sessionMgr.CreateCheckpoint(ctx, sessionID, fmt.Sprintf("pre-exec: %s", cmdDesc), nil)
		if cpErr != nil {
			// Best-effort: don't fail the exec, but surface the failure.
			s.logger.Warn("exec: pre-exec checkpoint failed", "session_id", sessionID, "error", cpErr)
		}
	}

	result, err := s.runner.Run(ctx, protoToRunRequest(req))
	if err != nil {
		// Post-exec error event.
		if sessionID != "" && s.sessionMgr != nil {
			eventData, _ := json.Marshal(map[string]any{
				"command": req.GetCommand(),
				"args":    req.GetArgs(),
				"error":   err.Error(),
			})
			if evErr := s.sessionMgr.AddEvent(ctx, sessionID, "error", eventData); evErr != nil {
				s.logger.Warn("exec: record error event failed", "session_id", sessionID, "error", evErr)
			}
		}
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}

	// Post-exec success event.
	if sessionID != "" && s.sessionMgr != nil {
		eventData, _ := json.Marshal(map[string]any{
			"command":   req.GetCommand(),
			"args":      req.GetArgs(),
			"exit_code": result.ExitCode,
		})
		if evErr := s.sessionMgr.AddEvent(ctx, sessionID, "command", eventData); evErr != nil {
			s.logger.Warn("exec: record command event failed", "session_id", sessionID, "error", evErr)
		}
	}

	return &v1.ExecResponse{
		ExitCode:   int32(result.ExitCode),
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		DurationMs: result.DurationMs,
	}, nil
}

// formatCommandDesc creates a short description of a command for checkpoint labels.
func formatCommandDesc(command string, args []string) string {
	if len(args) == 0 {
		return command
	}
	return command + " " + strings.Join(args, " ")
}

// ExecStream executes a command and streams output.
func (s *ExecServiceImpl) ExecStream(req *v1.ExecRequest, stream v1.ExecService_ExecStreamServer) error {
	onOutput := func(streamName string, data []byte) {
		out := &v1.ExecOutput{Data: data}
		if streamName == "stderr" {
			out.Stream = v1.ExecOutput_STDERR
		} else {
			out.Stream = v1.ExecOutput_STDOUT
		}
		if err := stream.Send(out); err != nil {
			// Client likely disconnected; log at debug to avoid noise.
			s.logger.Debug("exec: stream send failed", "error", err)
		}
	}

	result, err := s.runner.RunStream(stream.Context(), protoToRunRequest(req), onOutput)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "%v", err)
	}

	// Send final message with done=true and exit code.
	return stream.Send(&v1.ExecOutput{
		Done:     true,
		ExitCode: int32(result.ExitCode),
	})
}

func protoToRunRequest(req *v1.ExecRequest) *exec.RunRequest {
	r := &exec.RunRequest{
		Command:    req.Command,
		Args:       req.Args,
		WorkingDir: req.WorkingDir,
		Env:        req.Env,
		Background: req.Background,
	}
	if req.TimeoutSeconds > 0 {
		r.Timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	return r
}
