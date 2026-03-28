package grpc

import (
	"context"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/capture"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ v1.CaptureServiceServer = (*CaptureServiceImpl)(nil)

// CaptureServiceImpl implements the CaptureService gRPC service.
type CaptureServiceImpl struct {
	v1.UnimplementedCaptureServiceServer
}

// NewCaptureService creates a CaptureService implementation.
func NewCaptureService() *CaptureServiceImpl {
	return &CaptureServiceImpl{}
}

// Screenshot captures a screenshot of the specified display.
func (s *CaptureServiceImpl) Screenshot(_ context.Context, req *v1.ScreenshotRequest) (*v1.ScreenshotResponse, error) {
	display := int(req.GetDisplay())
	quality := int(req.GetQuality())

	data, format, err := capture.Screenshot(display, quality)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "screenshot failed: %v", err)
	}

	return &v1.ScreenshotResponse{
		Image:  data,
		Format: format,
	}, nil
}

// CaptureWindow captures a specific window by title.
// This requires Electron (sentinel-eye) and is not yet implemented.
func (s *CaptureServiceImpl) CaptureWindow(_ context.Context, _ *v1.CaptureWindowRequest) (*v1.CaptureWindowResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CaptureWindow requires sentinel-eye (Electron); not yet available")
}

// ListDisplays returns information about connected displays.
// Currently returns a single primary display entry.
func (s *CaptureServiceImpl) ListDisplays(_ context.Context, _ *v1.ListDisplaysRequest) (*v1.ListDisplaysResponse, error) {
	return &v1.ListDisplaysResponse{
		Displays: []*v1.DisplayInfo{
			{
				Index:   0,
				Name:    "Primary Display",
				Primary: true,
			},
		},
	}, nil
}
