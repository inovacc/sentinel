package grpc

import (
	"context"
	"time"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/worker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ v1.WorkerServiceServer = (*WorkerServiceImpl)(nil)

// WorkerServiceImpl implements the WorkerService gRPC service.
type WorkerServiceImpl struct {
	v1.UnimplementedWorkerServiceServer
	pool *worker.Pool
}

// NewWorkerService creates a WorkerService backed by the given pool.
func NewWorkerService(pool *worker.Pool) *WorkerServiceImpl {
	return &WorkerServiceImpl{pool: pool}
}

// Spawn starts a new worker process.
func (s *WorkerServiceImpl) Spawn(ctx context.Context, req *v1.SpawnWorkerRequest) (*v1.SpawnWorkerResponse, error) {
	var timeout time.Duration
	if req.GetTimeoutSeconds() > 0 {
		timeout = time.Duration(req.GetTimeoutSeconds()) * time.Second
	}

	w, err := s.pool.Spawn(ctx,
		req.GetCommand(),
		req.GetArgs(),
		req.GetWorkingDir(),
		req.GetEnv(),
		req.GetSessionId(),
		req.GetMetadata(),
		timeout,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "spawn: %v", err)
	}

	return &v1.SpawnWorkerResponse{
		WorkerId: w.ID,
		Pid:      int32(w.PID),
	}, nil
}

// List returns all workers with optional status filter.
func (s *WorkerServiceImpl) List(_ context.Context, req *v1.ListWorkersRequest) (*v1.ListWorkersResponse, error) {
	workers, err := s.pool.List(worker.Status(req.GetStatusFilter()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}

	infos := make([]*v1.WorkerInfo, 0, len(workers))
	for i := range workers {
		infos = append(infos, workerToProto(&workers[i]))
	}

	return &v1.ListWorkersResponse{
		Workers:     infos,
		ActiveCount: int32(s.pool.ActiveCount()),
		TotalCount:  int32(s.pool.TotalCount()),
	}, nil
}

// Get returns details for a specific worker.
func (s *WorkerServiceImpl) Get(_ context.Context, req *v1.GetWorkerRequest) (*v1.WorkerInfo, error) {
	w, err := s.pool.Get(req.GetWorkerId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "get: %v", err)
	}
	return workerToProto(w), nil
}

// Kill terminates a running worker.
func (s *WorkerServiceImpl) Kill(_ context.Context, req *v1.KillWorkerRequest) (*v1.KillWorkerResponse, error) {
	err := s.pool.Kill(req.GetWorkerId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "kill: %v", err)
	}
	return &v1.KillWorkerResponse{Killed: true}, nil
}

// KillAll terminates all running workers.
func (s *WorkerServiceImpl) KillAll(_ context.Context, _ *v1.KillAllWorkersRequest) (*v1.KillAllWorkersResponse, error) {
	killed, err := s.pool.KillAll()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "killall: %v", err)
	}
	return &v1.KillAllWorkersResponse{KilledCount: int32(killed)}, nil
}

// Wait polls for a worker to complete (every 500ms) and returns the final state.
func (s *WorkerServiceImpl) Wait(ctx context.Context, req *v1.WaitWorkerRequest) (*v1.WorkerInfo, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		w, err := s.pool.Get(req.GetWorkerId())
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "wait: %v", err)
		}
		if w.Status != worker.StatusRunning {
			return workerToProto(w), nil
		}

		select {
		case <-ctx.Done():
			return nil, status.Errorf(codes.DeadlineExceeded, "wait: context cancelled")
		case <-ticker.C:
			// poll again
		}
	}
}

// workerToProto maps an internal Worker to a proto WorkerInfo.
func workerToProto(w *worker.Worker) *v1.WorkerInfo {
	info := &v1.WorkerInfo{
		Id:         w.ID,
		Command:    w.Command,
		Args:       w.Args,
		Pid:        int32(w.PID),
		Status:     string(w.Status),
		CreatedAt:  w.CreatedAt.Unix(),
		StartedAt:  w.StartedAt.Unix(),
		Stdout:     w.Stdout,
		Stderr:     w.Stderr,
		ExitCode:   int32(w.ExitCode),
		SessionId:  w.SessionID,
		Metadata:   w.Metadata,
		DurationMs: w.DurationMs(),
	}
	if w.FinishedAt != nil {
		info.FinishedAt = w.FinishedAt.Unix()
	}
	return info
}
