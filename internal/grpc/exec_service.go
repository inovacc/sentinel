package grpc

import (
	"context"
	"time"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/exec"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ v1.ExecServiceServer = (*ExecServiceImpl)(nil)

// ExecServiceImpl implements the ExecService gRPC service.
type ExecServiceImpl struct {
	v1.UnimplementedExecServiceServer
	runner *exec.Runner
}

// NewExecService creates an ExecService backed by the given runner.
func NewExecService(runner *exec.Runner) *ExecServiceImpl {
	return &ExecServiceImpl{runner: runner}
}

// Exec executes a command and returns the result.
func (s *ExecServiceImpl) Exec(ctx context.Context, req *v1.ExecRequest) (*v1.ExecResponse, error) {
	result, err := s.runner.Run(ctx, protoToRunRequest(req))
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}

	return &v1.ExecResponse{
		ExitCode:   int32(result.ExitCode),
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		DurationMs: result.DurationMs,
	}, nil
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
