package grpc

import (
	"bytes"
	"context"
	"io"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/fs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const downloadChunkSize = 32 * 1024 // 32KB

// FileSystemServiceImpl implements the FileSystemService gRPC service.
type FileSystemServiceImpl struct {
	v1.UnimplementedFileSystemServiceServer
	fs *fs.Service
}

// NewFileSystemService creates a new FileSystemServiceImpl.
func NewFileSystemService(fsSvc *fs.Service) *FileSystemServiceImpl {
	return &FileSystemServiceImpl{fs: fsSvc}
}

// ReadFile reads a file within sandbox-allowed paths.
func (s *FileSystemServiceImpl) ReadFile(_ context.Context, req *v1.ReadFileRequest) (*v1.ReadFileResponse, error) {
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	content, size, mimeType, err := s.fs.ReadFile(req.GetPath(), req.GetOffset(), req.GetLimit())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read file: %v", err)
	}

	return &v1.ReadFileResponse{
		Content:  content,
		Size:     size,
		MimeType: mimeType,
	}, nil
}

// WriteFile writes content to a file within sandbox-allowed paths.
func (s *FileSystemServiceImpl) WriteFile(_ context.Context, req *v1.WriteFileRequest) (*v1.WriteFileResponse, error) {
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	written, err := s.fs.WriteFile(req.GetPath(), req.GetContent(), req.GetCreateDirs())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "write file: %v", err)
	}

	return &v1.WriteFileResponse{
		BytesWritten: written,
	}, nil
}

// ListDir lists directory contents within sandbox-allowed paths.
func (s *FileSystemServiceImpl) ListDir(_ context.Context, req *v1.ListDirRequest) (*v1.ListDirResponse, error) {
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	entries, err := s.fs.ListDir(req.GetPath(), req.GetRecursive())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list dir: %v", err)
	}

	protoEntries := make([]*v1.FileEntry, 0, len(entries))
	for _, e := range entries {
		protoEntries = append(protoEntries, &v1.FileEntry{
			Name:         e.Name,
			Path:         e.Path,
			IsDir:        e.IsDir,
			Size:         e.Size,
			ModifiedUnix: e.Modified,
			Mode:         e.Mode,
		})
	}

	return &v1.ListDirResponse{
		Entries: protoEntries,
	}, nil
}

// Upload receives a stream of UploadChunks and writes them to a file in the sandbox.
func (s *FileSystemServiceImpl) Upload(stream grpc.ClientStreamingServer[v1.UploadChunk, v1.UploadResponse]) error {
	var (
		buf        bytes.Buffer
		targetPath string
	)

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Errorf(codes.Internal, "recv chunk: %v", err)
		}

		// Use the target path from the first chunk.
		if targetPath == "" {
			targetPath = chunk.GetTargetPath()
			if targetPath == "" {
				return status.Error(codes.InvalidArgument, "target_path is required in the first chunk")
			}
		}

		_, _ = buf.Write(chunk.GetData())

		if chunk.GetIsLast() {
			break
		}
	}

	if targetPath == "" {
		return status.Error(codes.InvalidArgument, "no chunks received")
	}

	written, err := s.fs.WriteFile(targetPath, buf.Bytes(), true)
	if err != nil {
		return status.Errorf(codes.Internal, "write uploaded file: %v", err)
	}

	return stream.SendAndClose(&v1.UploadResponse{
		TotalBytes: written,
		Path:       targetPath,
	})
}

// Download reads a file and sends it as a stream of 32KB chunks.
func (s *FileSystemServiceImpl) Download(req *v1.DownloadRequest, stream grpc.ServerStreamingServer[v1.DownloadChunk]) error {
	if req.GetPath() == "" {
		return status.Error(codes.InvalidArgument, "path is required")
	}

	// Read the full file content using the fs service (which checks sandbox permissions).
	content, _, _, err := s.fs.ReadFile(req.GetPath(), 0, 0)
	if err != nil {
		return status.Errorf(codes.Internal, "read file for download: %v", err)
	}

	reader := bytes.NewReader(content)
	buf := make([]byte, downloadChunkSize)

	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			isLast := readErr == io.EOF
			if sendErr := stream.Send(&v1.DownloadChunk{
				Data:   buf[:n],
				IsLast: isLast,
			}); sendErr != nil {
				return status.Errorf(codes.Internal, "send chunk: %v", sendErr)
			}
			if isLast {
				return nil
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return status.Errorf(codes.Internal, "read chunk: %v", readErr)
		}
	}
}

// Delete deletes a file within sandbox-allowed paths.
func (s *FileSystemServiceImpl) Delete(_ context.Context, req *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	if err := s.fs.DeleteFile(req.GetPath()); err != nil {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}

	return &v1.DeleteResponse{
		Deleted: true,
	}, nil
}

// Glob matches files using a glob pattern within the sandbox.
func (s *FileSystemServiceImpl) Glob(_ context.Context, req *v1.GlobRequest) (*v1.GlobResponse, error) {
	if req.GetPattern() == "" {
		return nil, status.Error(codes.InvalidArgument, "pattern is required")
	}

	matches, err := s.fs.Glob(req.GetPattern(), req.GetBasePath())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "glob: %v", err)
	}

	return &v1.GlobResponse{
		Matches: matches,
	}, nil
}

// Grep searches file contents within sandbox-allowed paths.
func (s *FileSystemServiceImpl) Grep(_ context.Context, req *v1.GrepRequest) (*v1.GrepResponse, error) {
	if req.GetPattern() == "" {
		return nil, status.Error(codes.InvalidArgument, "pattern is required")
	}
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	matches, err := s.fs.Grep(req.GetPattern(), req.GetPath(), req.GetRecursive(), req.GetIgnoreCase(), int(req.GetContextLines()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "grep: %v", err)
	}

	protoMatches := make([]*v1.GrepMatch, 0, len(matches))
	for _, m := range matches {
		protoMatches = append(protoMatches, &v1.GrepMatch{
			File:          m.File,
			Line:          int32(m.Line),
			Text:          m.Text,
			ContextBefore: m.ContextBefore,
			ContextAfter:  m.ContextAfter,
		})
	}

	return &v1.GrepResponse{
		Matches: protoMatches,
	}, nil
}

// Ensure compile-time interface satisfaction.
var _ v1.FileSystemServiceServer = (*FileSystemServiceImpl)(nil)

