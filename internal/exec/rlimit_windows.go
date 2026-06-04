//go:build windows

package exec

import "os"

// rlimitSignalKill is always false on Windows: process resource caps are enforced
// by the Job Object, which terminates over-limit children without surfacing a
// Unix-style rlimit signal. The Job Object owns that path, so no proc_rlimit
// breach is emitted from the exec layer on Windows.
func rlimitSignalKill(_ *os.ProcessState) bool { return false }
