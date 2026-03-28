package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrAccessDenied    = errors.New("access denied")
	ErrPathTraversal   = errors.New("path traversal detected")
	ErrBlockedCommand  = errors.New("command is blocked")
	ErrExecNotAllowed  = errors.New("executable not in allowlist")
	ErrInvalidPath     = errors.New("invalid path")
	ErrDeleteRoot      = errors.New("cannot delete sandbox root")
	ErrAbsoluteExec    = errors.New("exec command must be a binary name, not a path")
)

// Sandbox enforces path-based access control.
// Write/delete operations are restricted to the sandbox root.
// Read operations are allowed for paths matching the allowlist OR within sandbox root.
// Exec operations only allow binaries in the exec allowlist.
type Sandbox struct {
	root   string // absolute path to sandbox directory
	config Config
}

// Config defines the sandbox access control rules.
type Config struct {
	Root            string   // sandbox root directory
	ReadPatterns    []string // glob patterns for read access outside sandbox
	ExecAllowlist   []string // allowed executable names (e.g., "go", "git", "npm")
	BlockedCommands []string // always blocked command patterns
}

// New creates a new Sandbox, resolving the root to an absolute path and creating
// the directory if it does not exist.
func New(cfg Config) (*Sandbox, error) {
	if cfg.Root == "" {
		return nil, fmt.Errorf("%w: sandbox root must not be empty", ErrInvalidPath)
	}

	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("resolving sandbox root: %w", err)
	}

	root = filepath.Clean(root)

	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("creating sandbox root %q: %w", root, err)
	}

	// Resolve symlinks for the root itself so all comparisons use the real path.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolving symlinks for sandbox root: %w", err)
	}

	return &Sandbox{
		root:   resolved,
		config: cfg,
	}, nil
}

// CheckRead validates that the given path is allowed for read access.
// A path is readable if it is within the sandbox root OR matches a configured
// read pattern.
func (s *Sandbox) CheckRead(path string) error {
	resolved, err := s.ResolvePath(path)
	if err != nil {
		return fmt.Errorf("%w: read access denied for %q: %v", ErrAccessDenied, path, err)
	}

	if isSubPath(s.root, resolved) {
		return nil
	}

	if matchesAnyPattern(resolved, s.config.ReadPatterns) {
		return nil
	}

	return fmt.Errorf("%w: read access denied for %q (not in sandbox and no matching read pattern)", ErrAccessDenied, path)
}

// CheckWrite validates that the given path is allowed for write access.
// Write operations are only permitted within the sandbox root.
func (s *Sandbox) CheckWrite(path string) error {
	if containsTraversal(path) {
		return fmt.Errorf("%w: write path %q contains directory traversal", ErrPathTraversal, path)
	}

	resolved, err := s.ResolvePath(path)
	if err != nil {
		return fmt.Errorf("%w: write access denied for %q: %v", ErrAccessDenied, path, err)
	}

	if !isSubPath(s.root, resolved) {
		return fmt.Errorf("%w: write access denied for %q (outside sandbox root)", ErrAccessDenied, path)
	}

	return nil
}

// CheckDelete validates that the given path is allowed for deletion.
// Delete operations are only permitted within the sandbox root.
// Deleting the sandbox root itself is always refused.
func (s *Sandbox) CheckDelete(path string) error {
	if containsTraversal(path) {
		return fmt.Errorf("%w: delete path %q contains directory traversal", ErrPathTraversal, path)
	}

	resolved, err := s.ResolvePath(path)
	if err != nil {
		return fmt.Errorf("%w: delete access denied for %q: %v", ErrAccessDenied, path, err)
	}

	// Refuse deletion of the sandbox root itself.
	if resolved == s.root {
		return fmt.Errorf("%w: refusing to delete sandbox root %q", ErrDeleteRoot, s.root)
	}

	if !isSubPath(s.root, resolved) {
		return fmt.Errorf("%w: delete access denied for %q (outside sandbox root)", ErrAccessDenied, path)
	}

	return nil
}

// CheckExec validates that the command is permitted for execution.
// The command must be a bare binary name (no path separators) and must
// appear in the exec allowlist. It must not match any blocked command pattern.
func (s *Sandbox) CheckExec(command string, args []string) error {
	// Reject commands that look like paths.
	if strings.Contains(command, string(filepath.Separator)) || strings.Contains(command, "/") {
		return fmt.Errorf("%w: got %q", ErrAbsoluteExec, command)
	}

	if isBlockedCommand(command, args, s.config.BlockedCommands) {
		return fmt.Errorf("%w: %q is blocked", ErrBlockedCommand, command)
	}

	for _, allowed := range s.config.ExecAllowlist {
		if command == allowed {
			return nil
		}
	}

	return fmt.Errorf("%w: %q is not in the exec allowlist", ErrExecNotAllowed, command)
}

// ResolvePath resolves a path to its absolute, clean, symlink-evaluated form.
// Relative paths are resolved against the sandbox root.
func (s *Sandbox) ResolvePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: empty path", ErrInvalidPath)
	}

	var abs string
	if filepath.IsAbs(path) {
		abs = filepath.Clean(path)
	} else {
		abs = filepath.Clean(filepath.Join(s.root, path))
	}

	// Try to resolve symlinks. If the path does not exist yet (e.g., for write),
	// resolve as much of the parent as possible.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Path may not exist yet — resolve the parent directory instead.
		dir := filepath.Dir(abs)
		base := filepath.Base(abs)

		resolvedDir, dirErr := filepath.EvalSymlinks(dir)
		if dirErr != nil {
			// Parent doesn't exist either; use the cleaned absolute path.
			return abs, nil
		}

		return filepath.Join(resolvedDir, base), nil
	}

	return resolved, nil
}

// SandboxPath joins a relative path with the sandbox root safely.
func (s *Sandbox) SandboxPath(relative string) string {
	return filepath.Join(s.root, filepath.Clean(relative))
}

// Root returns the sandbox root directory (absolute, symlink-resolved).
func (s *Sandbox) Root() string {
	return s.root
}
