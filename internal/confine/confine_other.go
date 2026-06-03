//go:build !windows

package confine

import "log/slog"

func newConfiner(_ Config, _ *slog.Logger) (Confiner, error) {
	return noopConfiner{}, nil
}
