//go:build !windows

package exec

import "os/exec"

// Shell returns the platform-appropriate shell and its command flag.
func Shell() (string, string) {
	if path, err := exec.LookPath("bash"); err == nil {
		_ = path
		return "bash", "-c"
	}
	return "sh", "-c"
}

// LookupExecutable finds the full path of an executable in PATH.
func LookupExecutable(name string) (string, error) {
	return exec.LookPath(name)
}
