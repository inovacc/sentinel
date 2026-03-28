package grpc

import (
	"context"
	"encoding/json"
	"fmt"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ v1.SessionServiceServer = (*SessionServiceImpl)(nil)

// SessionServiceImpl implements the SessionService gRPC service.
type SessionServiceImpl struct {
	v1.UnimplementedSessionServiceServer
	mgr *session.Manager
}

// NewSessionService creates a SessionService backed by the given manager.
func NewSessionService(mgr *session.Manager) *SessionServiceImpl {
	return &SessionServiceImpl{mgr: mgr}
}

func (s *SessionServiceImpl) Create(ctx context.Context, req *v1.CreateSessionRequest) (*v1.CreateSessionResponse, error) {
	sess, err := s.mgr.Create(ctx, req.DeviceId, req.ProjectName, req.Description, req.WorkingDir, req.Env)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create session: %v", err)
	}
	return &v1.CreateSessionResponse{
		SessionId: sess.ID,
		DeviceId:  sess.DeviceID,
	}, nil
}

func (s *SessionServiceImpl) Resume(ctx context.Context, req *v1.ResumeSessionRequest) (*v1.ResumeSessionResponse, error) {
	sess, checkpoint, events, err := s.mgr.Resume(ctx, req.SessionId)
	if err != nil {
		return nil, sessionError(err)
	}

	resp := &v1.ResumeSessionResponse{
		SessionId: sess.ID,
		Status:    string(sess.Status),
		ErrorInfo: sess.ErrorInfo,
	}

	if sess.Context != nil {
		resp.Context = sessionCtxToProto(sess.Context)
	}
	if checkpoint != nil {
		resp.LastCheckpoint = checkpointToProto(checkpoint)
	}
	for _, ev := range events {
		resp.RecentEvents = append(resp.RecentEvents, eventToProto(&ev))
	}

	return resp, nil
}

func (s *SessionServiceImpl) Pause(ctx context.Context, req *v1.PauseSessionRequest) (*v1.PauseSessionResponse, error) {
	cp, err := s.mgr.Pause(ctx, req.SessionId, req.Reason)
	if err != nil {
		return nil, sessionError(err)
	}
	return &v1.PauseSessionResponse{
		Success:      true,
		CheckpointId: fmt.Sprintf("%d", cp.ID),
	}, nil
}

func (s *SessionServiceImpl) Status(ctx context.Context, req *v1.SessionStatusRequest) (*v1.SessionStatusResponse, error) {
	sess, err := s.mgr.Get(ctx, req.SessionId)
	if err != nil {
		return nil, sessionError(err)
	}

	resp := &v1.SessionStatusResponse{
		SessionId: sess.ID,
		DeviceId:  sess.DeviceID,
		Status:    string(sess.Status),
		CreatedAt: sess.CreatedAt.Unix(),
		UpdatedAt: sess.UpdatedAt.Unix(),
		ErrorInfo: sess.ErrorInfo,
	}

	if sess.ResumedAt != nil {
		resp.ResumedAt = sess.ResumedAt.Unix()
	}
	if sess.Context != nil {
		resp.Context = sessionCtxToProto(sess.Context)
	}
	if sess.Metadata != nil {
		data, _ := json.Marshal(sess.Metadata)
		resp.Metadata = string(data)
	}

	return resp, nil
}

func (s *SessionServiceImpl) List(ctx context.Context, req *v1.ListSessionsRequest) (*v1.ListSessionsResponse, error) {
	limit := int(req.Limit)
	if limit == 0 {
		limit = 50
	}

	sessions, err := s.mgr.List(ctx, req.DeviceId, session.Status(req.StatusFilter), limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}

	resp := &v1.ListSessionsResponse{}
	for _, sess := range sessions {
		summary := &v1.SessionSummary{
			SessionId: sess.ID,
			DeviceId:  sess.DeviceID,
			Status:    string(sess.Status),
			CreatedAt: sess.CreatedAt.Unix(),
			UpdatedAt: sess.UpdatedAt.Unix(),
			ErrorInfo: sess.ErrorInfo,
		}
		if sess.Context != nil {
			summary.ProjectName = sess.Context.ProjectName
		}
		resp.Sessions = append(resp.Sessions, summary)
	}

	return resp, nil
}

func (s *SessionServiceImpl) Destroy(ctx context.Context, req *v1.DestroySessionRequest) (*v1.DestroySessionResponse, error) {
	if err := s.mgr.Destroy(ctx, req.SessionId); err != nil {
		return nil, sessionError(err)
	}
	return &v1.DestroySessionResponse{Success: true}, nil
}

func (s *SessionServiceImpl) Checkpoint(ctx context.Context, req *v1.CheckpointRequest) (*v1.CheckpointResponse, error) {
	// Get current session context for the checkpoint.
	sess, err := s.mgr.Get(ctx, req.SessionId)
	if err != nil {
		return nil, sessionError(err)
	}

	cp, err := s.mgr.CreateCheckpoint(ctx, req.SessionId, req.Description, sess.Context)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create checkpoint: %v", err)
	}

	return &v1.CheckpointResponse{
		CheckpointId: fmt.Sprintf("%d", cp.ID),
		Timestamp:    cp.Timestamp.Unix(),
	}, nil
}

func (s *SessionServiceImpl) Heartbeat(ctx context.Context, req *v1.HeartbeatRequest) (*v1.HeartbeatResponse, error) {
	if err := s.mgr.Heartbeat(ctx, req.SessionId); err != nil {
		return nil, sessionError(err)
	}
	return &v1.HeartbeatResponse{
		Alive:  true,
		Status: "active",
	}, nil
}

// --- conversion helpers ---

func sessionCtxToProto(c *session.SessionContext) *v1.SessionContext {
	if c == nil {
		return nil
	}
	return &v1.SessionContext{
		WorkingDir:   c.WorkingDir,
		Env:          c.Env,
		LastCommand:  c.LastCommand,
		LastOutput:   c.LastOutput,
		LastExitCode: int32(c.LastExitCode),
		ProjectName:  c.ProjectName,
	}
}

func checkpointToProto(cp *session.Checkpoint) *v1.SessionCheckpoint {
	if cp == nil {
		return nil
	}
	return &v1.SessionCheckpoint{
		Id:          fmt.Sprintf("%d", cp.ID),
		Timestamp:   cp.Timestamp.Unix(),
		State:       sessionCtxToProto(cp.State),
		Description: cp.Description,
	}
}

func eventToProto(ev *session.Event) *v1.SessionEvent {
	return &v1.SessionEvent{
		Timestamp: ev.Timestamp.Unix(),
		EventType: ev.Type,
		Summary:   string(ev.Data),
		Sequence:  int32(ev.Sequence),
	}
}

func sessionError(err error) error {
	errStr := err.Error()
	// Check for common error patterns.
	switch {
	case contains(errStr, "not found"), contains(errStr, "no rows"):
		return status.Errorf(codes.NotFound, "%v", err)
	case contains(errStr, "cannot"), contains(errStr, "invalid state"):
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
