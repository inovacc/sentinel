package confine

import (
	"fmt"
	"strconv"
)

// TrampolineSubcommand is the hidden cobra subcommand the daemon re-execs into
// to apply Unix rlimits before exec'ing the real target.
const TrampolineSubcommand = "__confined-exec"

// trampolinePrefix builds the argv prefix that re-invokes the daemon binary as
// the rlimit trampoline. The caller prepends os.Executable() and appends the
// real command + args after the "--" terminator.
func trampolinePrefix(c Config) []string {
	return []string{
		TrampolineSubcommand,
		"--as", strconv.FormatUint(c.ProcMaxMemoryBytes, 10),
		"--nofile", strconv.FormatUint(c.ProcMaxOpenFiles, 10),
		"--cpu", strconv.FormatUint(c.ProcMaxCPUSeconds, 10),
		"--",
	}
}

// ParseTrampolineArgs parses the trampoline subcommand's args, returning the
// three rlimit values and the remaining target command argv (after "--").
func ParseTrampolineArgs(args []string) (as, nofile, cpu uint64, rest []string, err error) {
	i := 0
	readU := func() (uint64, error) {
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("confined-exec: missing value for %q", args[i-1])
		}
		v, perr := strconv.ParseUint(args[i], 10, 64)
		i++
		return v, perr
	}
	for i < len(args) {
		switch args[i] {
		case "--as":
			as, err = readU()
		case "--nofile":
			nofile, err = readU()
		case "--cpu":
			cpu, err = readU()
		case "--":
			rest = args[i+1:]
			return as, nofile, cpu, rest, nil
		default:
			return 0, 0, 0, nil, fmt.Errorf("confined-exec: unexpected arg %q", args[i])
		}
		if err != nil {
			return 0, 0, 0, nil, fmt.Errorf("confined-exec: parse %q: %w", args[i-1], err)
		}
	}
	return as, nofile, cpu, nil, fmt.Errorf("confined-exec: missing -- terminator")
}
