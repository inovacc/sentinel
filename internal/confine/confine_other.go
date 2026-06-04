//go:build !windows && !linux && !darwin

package confine

import "log/slog"

func newConfiner(_ Config, _ *slog.Logger) (Confiner, error) {
	return noopConfiner{}, nil
}
