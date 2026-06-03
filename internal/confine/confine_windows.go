//go:build windows

package confine

import "log/slog"

// newConfiner is a temporary Task-1 stub so the package builds and the no-op
// tests pass on Windows. Task 3 replaces this file with the real Job Object +
// restricted token confiner.
func newConfiner(_ Config, _ *slog.Logger) (Confiner, error) {
	return noopConfiner{}, nil
}
