package logrotate

import (
	"fmt"
	"os"
	"sync"
)

// Writer implements io.Writer with size-based log rotation.
type Writer struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	maxSize  int64
	maxFiles int
	size     int64
}

// New opens or creates a log file at path with rotation settings.
// maxSizeMB is the maximum size in megabytes before rotation.
// maxFiles is the maximum number of rotated files to keep.
func New(path string, maxSizeMB, maxFiles int) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat log file: %w", err)
	}

	return &Writer{
		file:     f,
		path:     path,
		maxSize:  int64(maxSizeMB) * 1024 * 1024,
		maxFiles: maxFiles,
		size:     info.Size(),
	}, nil
}

// Write writes bytes to the log file, rotating if the size limit is exceeded.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, fmt.Errorf("rotate: %w", err)
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// rotate renames the current log file and opens a new one.
// Existing rotated files are shifted: .1 -> .2, .2 -> .3, etc.
// Files beyond maxFiles are removed.
func (w *Writer) rotate() error {
	// Close current file.
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close current: %w", err)
	}

	// Remove the oldest rotated file if it exceeds maxFiles.
	oldest := fmt.Sprintf("%s.%d", w.path, w.maxFiles)
	_ = os.Remove(oldest)

	// Shift existing rotated files.
	for i := w.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		_ = os.Rename(src, dst)
	}

	// Rename current to .1
	if err := os.Rename(w.path, w.path+".1"); err != nil {
		return fmt.Errorf("rename current to .1: %w", err)
	}

	// Open a fresh log file.
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open new log file: %w", err)
	}
	w.file = f
	w.size = 0
	return nil
}
