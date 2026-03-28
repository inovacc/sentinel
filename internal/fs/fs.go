package fs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/inovacc/sentinel/internal/sandbox"
)

// FileEntry describes a single file or directory.
type FileEntry struct {
	Name     string
	Path     string
	IsDir    bool
	Size     int64
	Modified int64  // unix timestamp
	Mode     string // e.g. "-rwxr-xr-x"
}

// GrepMatch describes a single match found by Grep.
type GrepMatch struct {
	File          string
	Line          int
	Text          string
	ContextBefore []string
	ContextAfter  []string
}

// mimeTypes maps file extensions to MIME types.
var mimeTypes = map[string]string{
	".go":    "text/x-go",
	".py":    "text/x-python",
	".js":    "text/javascript",
	".ts":    "text/typescript",
	".json":  "application/json",
	".yaml":  "text/yaml",
	".yml":   "text/yaml",
	".xml":   "application/xml",
	".html":  "text/html",
	".htm":   "text/html",
	".css":   "text/css",
	".md":    "text/markdown",
	".txt":   "text/plain",
	".sh":    "text/x-shellscript",
	".bash":  "text/x-shellscript",
	".toml":  "text/toml",
	".rs":    "text/x-rust",
	".java":  "text/x-java",
	".c":     "text/x-c",
	".h":     "text/x-c",
	".cpp":   "text/x-c++",
	".hpp":   "text/x-c++",
	".rb":    "text/x-ruby",
	".php":   "text/x-php",
	".proto": "text/x-protobuf",
	".sql":   "text/x-sql",
	".csv":   "text/csv",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".pdf":   "application/pdf",
	".zip":   "application/zip",
	".tar":   "application/x-tar",
	".gz":    "application/gzip",
}

// Service handles sandboxed file operations.
type Service struct {
	sandbox *sandbox.Sandbox
}

// NewService creates a new file system service backed by the given sandbox.
func NewService(sb *sandbox.Sandbox) *Service {
	return &Service{sandbox: sb}
}

// detectMIME returns a MIME type based on the file extension.
func detectMIME(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if mt, ok := mimeTypes[ext]; ok {
		return mt
	}
	return "application/octet-stream"
}

// ReadFile reads a file within sandbox read-allowed paths.
// offset and limit control which portion of the file to return. If limit <= 0,
// the entire file (from offset) is returned.
func (s *Service) ReadFile(path string, offset, limit int64) (content []byte, size int64, mimeType string, err error) {
	if err := s.sandbox.CheckRead(path); err != nil {
		return nil, 0, "", err
	}

	resolved, err := s.sandbox.ResolvePath(path)
	if err != nil {
		return nil, 0, "", fmt.Errorf("resolve path: %w", err)
	}

	fi, err := os.Stat(resolved)
	if err != nil {
		return nil, 0, "", fmt.Errorf("stat: %w", err)
	}

	size = fi.Size()
	mimeType = detectMIME(resolved)

	f, err := os.Open(resolved)
	if err != nil {
		return nil, 0, "", fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, 0, "", fmt.Errorf("seek: %w", err)
		}
	}

	var reader io.Reader = f
	if limit > 0 {
		reader = io.LimitReader(f, limit)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, 0, "", fmt.Errorf("read: %w", err)
	}

	return data, size, mimeType, nil
}

// WriteFile writes content to a file within sandbox write-allowed paths.
// If createDirs is true, parent directories are created as needed.
// Returns the number of bytes written.
func (s *Service) WriteFile(path string, content []byte, createDirs bool) (int64, error) {
	if err := s.sandbox.CheckWrite(path); err != nil {
		return 0, err
	}

	resolved, err := s.sandbox.ResolvePath(path)
	if err != nil {
		return 0, fmt.Errorf("resolve path: %w", err)
	}

	if createDirs {
		dir := filepath.Dir(resolved)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return 0, fmt.Errorf("create dirs: %w", err)
		}
	}

	if err := os.WriteFile(resolved, content, 0o644); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	return int64(len(content)), nil
}

// ListDir lists directory contents within sandbox read-allowed paths.
// If recursive is true, subdirectories are traversed.
func (s *Service) ListDir(path string, recursive bool) ([]FileEntry, error) {
	if err := s.sandbox.CheckRead(path); err != nil {
		return nil, err
	}

	resolved, err := s.sandbox.ResolvePath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	var entries []FileEntry

	if recursive {
		err = filepath.Walk(resolved, func(p string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			// Skip the root directory itself.
			if p == resolved {
				return nil
			}
			entries = append(entries, fileInfoToEntry(p, info))
			return nil
		})
	} else {
		dirEntries, readErr := os.ReadDir(resolved)
		if readErr != nil {
			return nil, fmt.Errorf("readdir: %w", readErr)
		}
		for _, de := range dirEntries {
			info, infoErr := de.Info()
			if infoErr != nil {
				return nil, fmt.Errorf("info for %s: %w", de.Name(), infoErr)
			}
			entries = append(entries, fileInfoToEntry(filepath.Join(resolved, de.Name()), info))
		}
	}

	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}

	return entries, nil
}

// DeleteFile deletes a file within sandbox delete-allowed paths.
func (s *Service) DeleteFile(path string) error {
	if err := s.sandbox.CheckDelete(path); err != nil {
		return err
	}

	resolved, err := s.sandbox.ResolvePath(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	if err := os.Remove(resolved); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	return nil
}

// Glob matches files using a glob pattern within the sandbox.
// basePath is resolved relative to the sandbox root if not absolute.
func (s *Service) Glob(pattern, basePath string) ([]string, error) {
	if basePath == "" {
		basePath = s.sandbox.Root()
	}

	if err := s.sandbox.CheckRead(basePath); err != nil {
		return nil, err
	}

	resolved, err := s.sandbox.ResolvePath(basePath)
	if err != nil {
		return nil, fmt.Errorf("resolve base path: %w", err)
	}

	fullPattern := filepath.Join(resolved, pattern)
	matches, err := filepath.Glob(fullPattern)
	if err != nil {
		return nil, fmt.Errorf("glob: %w", err)
	}

	return matches, nil
}

// Grep searches file contents for a regex pattern within sandbox read-allowed paths.
// If path points to a directory and recursive is true, all files are searched.
// contextLines specifies how many lines before/after each match to include.
func (s *Service) Grep(pattern, path string, recursive, ignoreCase bool, contextLines int) ([]GrepMatch, error) {
	if err := s.sandbox.CheckRead(path); err != nil {
		return nil, err
	}

	resolved, err := s.sandbox.ResolvePath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	flags := ""
	if ignoreCase {
		flags = "(?i)"
	}
	re, err := regexp.Compile(flags + pattern)
	if err != nil {
		return nil, fmt.Errorf("compile pattern: %w", err)
	}

	fi, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	var matches []GrepMatch

	if fi.IsDir() {
		walkErr := filepath.Walk(resolved, func(p string, info os.FileInfo, wErr error) error {
			if wErr != nil {
				return wErr
			}
			if info.IsDir() {
				if !recursive && p != resolved {
					return filepath.SkipDir
				}
				return nil
			}
			fileMatches, gErr := grepFile(p, re, contextLines)
			if gErr != nil {
				// Skip files we cannot read (e.g. binary).
				return nil
			}
			matches = append(matches, fileMatches...)
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("walk: %w", walkErr)
		}
	} else {
		fileMatches, gErr := grepFile(resolved, re, contextLines)
		if gErr != nil {
			return nil, gErr
		}
		matches = fileMatches
	}

	return matches, nil
}

// grepFile searches a single file for regex matches and returns them with context.
func grepFile(path string, re *regexp.Regexp, contextLines int) ([]GrepMatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var matches []GrepMatch
	for i, line := range lines {
		if re.MatchString(line) {
			m := GrepMatch{
				File: path,
				Line: i + 1,
				Text: line,
			}

			// Context before.
			start := i - contextLines
			if start < 0 {
				start = 0
			}
			if contextLines > 0 {
				m.ContextBefore = make([]string, 0, i-start)
				for j := start; j < i; j++ {
					m.ContextBefore = append(m.ContextBefore, lines[j])
				}
			}

			// Context after.
			end := i + contextLines + 1
			if end > len(lines) {
				end = len(lines)
			}
			if contextLines > 0 {
				m.ContextAfter = make([]string, 0, end-i-1)
				for j := i + 1; j < end; j++ {
					m.ContextAfter = append(m.ContextAfter, lines[j])
				}
			}

			matches = append(matches, m)
		}
	}

	return matches, nil
}

// fileInfoToEntry converts an os.FileInfo to a FileEntry.
func fileInfoToEntry(path string, info os.FileInfo) FileEntry {
	return FileEntry{
		Name:     info.Name(),
		Path:     path,
		IsDir:    info.IsDir(),
		Size:     info.Size(),
		Modified: info.ModTime().Unix(),
		Mode:     info.Mode().String(),
	}
}
