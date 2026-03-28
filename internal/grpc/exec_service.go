package grpc

import (
	"context"
	"encoding/json"
	"fmt"
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
}

// NewExecService creates an ExecService backed by the given runner.
// sessionMgr is optional; when non-nil, exec calls with a session_id will
// automatically create checkpoints before execution and record events after.
func NewExecService(runner *exec.Runner, sessionMgr *session.Manager) *ExecServiceImpl {
	return &ExecServiceImpl{runner: runner, sessionMgr: sessionMgr}
}

// Exec executes a command and returns the result.
func (s *ExecServiceImpl) Exec(ctx context.Context, req *v1.ExecRequest) (*v1.ExecResponse, error) {
	sessionID := req.GetSessionId()

	// Pre-exec checkpoint.
	if sessionID != "" && s.sessionMgr != nil {
		cmdDesc := formatCommandDesc(req.GetCommand(), req.GetArgs())
		_, cpErr := s.sessionMgr.CreateCheckpoint(ctx, sessionID, fmt.Sprintf("pre-exec: %s", cmdDesc), nil)
		if cpErr != nil {
			// Log but don't fail the exec — checkpoint is best-effort.
			_ = cpErr
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
			_ = s.sessionMgr.AddEvent(ctx, sessionID, "error", eventData)
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
		_ = s.sessionMgr.AddEvent(ctx, sessionID, "command", eventData)
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
		_ = stream.Send(out)
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
	}
	if req.TimeoutSeconds > 0 {
		r.Timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	return r
}
