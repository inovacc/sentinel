package grpc

import (
	"context"
	"encoding/json"
	"time"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/payload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ v1.PayloadServiceServer = (*PayloadServiceImpl)(nil)

// PayloadServiceImpl implements the PayloadService gRPC service.
type PayloadServiceImpl struct {
	v1.UnimplementedPayloadServiceServer
	registry *payload.Registry
}

// NewPayloadService creates a PayloadService backed by the given handler registry.
func NewPayloadService(registry *payload.Registry) *PayloadServiceImpl {
	return &PayloadServiceImpl{registry: registry}
}

// Send processes a structured JSON payload and returns a JSON response.
func (s *PayloadServiceImpl) Send(ctx context.Context, req *v1.PayloadRequest) (*v1.PayloadResponse, error) {
	if req.Action == "" {
		return nil, status.Error(codes.InvalidArgument, "action is required")
	}

	var rawPayload json.RawMessage
	if req.Payload != "" {
		rawPayload = json.RawMessage(req.Payload)
	}

	start := time.Now()
	respData, err := s.registry.Handle(ctx, req.Action, rawPayload)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		return &v1.PayloadResponse{
			Action:     req.Action,
			Success:    false,
			Error:      err.Error(),
			DurationMs: duration,
		}, nil
	}

	return &v1.PayloadResponse{
		Action:     req.Action,
		Payload:    string(respData),
		Success:    true,
		DurationMs: duration,
	}, nil
}

// SendStream processes a payload and streams the response in chunks.
func (s *PayloadServiceImpl) SendStream(req *v1.PayloadRequest, stream v1.PayloadService_SendStreamServer) error {
	// For now, handle as a single response sent as one chunk.
	resp, err := s.Send(stream.Context(), req)
	if err != nil {
		return err
	}

	return stream.Send(&v1.PayloadChunk{
		Data: resp.Payload,
		Done: true,
	})
}
