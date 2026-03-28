package sandbox

import (
	"path/filepath"
	"strings"
)

// isSubPath reports whether child is under parent after resolving both to
// absolute, clean paths and following symlinks.
func isSubPath(parent, child string) bool {
	cleanParent := filepath.Clean(parent)
	cleanChild := filepath.Clean(child)

	// Resolve symlinks for both paths, falling back to cleaned versions.
	resolvedParent, err := filepath.EvalSymlinks(cleanParent)
	if err != nil {
		resolvedParent = cleanParent
	}

	resolvedChild, err := filepath.EvalSymlinks(cleanChild)
	if err != nil {
		resolvedChild = cleanChild
	}

	// Normalize to use consistent separators.
	resolvedParent = filepath.ToSlash(resolvedParent)
	resolvedChild = filepath.ToSlash(resolvedChild)

	// The child must be strictly under the parent (not equal to it for sub-path).
	if resolvedChild == resolvedParent {
		return true
	}

	// Ensure parent ends with a slash for prefix matching to avoid
	// false positives like /sandbox-extra matching /sandbox.
	prefix := resolvedParent
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	return strings.HasPrefix(resolvedChild, prefix)
}

// matchesAnyPattern reports whether the given path matches any of the provided
// glob patterns using filepath.Match.
func matchesAnyPattern(path string, patterns []string) bool {
	// Normalize to forward slashes for consistent matching.
	normalized := filepath.ToSlash(path)

	for _, pattern := range patterns {
		normalizedPattern := filepath.ToSlash(pattern)

		matched, err := filepath.Match(normalizedPattern, normalized)
		if err == nil && matched {
			return true
		}

		// Also try matching just the base name against the pattern.
		base := filepath.Base(normalized)
		matched, err = filepath.Match(normalizedPattern, base)
		if err == nil && matched {
			return true
		}
	}

	return false
}

// containsTraversal reports whether the path contains ".." components that
// could be used to escape a directory boundary.
func containsTraversal(path string) bool {
	// Normalize separators.
	normalized := filepath.ToSlash(path)

	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		if part == ".." {
			return true
		}
	}

	return false
}

// isBlockedCommand reports whether the command with its arguments matches any
// blocked pattern. It checks the full command string "cmd arg1 arg2 ..." against
// each blocked pattern, as well as the command name alone.
func isBlockedCommand(cmd string, args []string, blocked []string) bool {
	full := cmd
	if len(args) > 0 {
		full = cmd + " " + strings.Join(args, " ")
	}

	for _, pattern := range blocked {
		// Exact match on command name.
		if cmd == pattern {
			return true
		}

		// Check if the full command string contains the blocked pattern.
		if strings.Contains(full, pattern) {
			return true
		}
	}

	return false
}

// sanitizePath cleans and normalizes a path for the current platform.
func sanitizePath(path string) string {
	return filepath.Clean(path)
}
