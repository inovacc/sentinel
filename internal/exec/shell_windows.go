//go:build windows

package exec

import "os/exec"

// Shell returns the platform-appropriate shell and its command flag.
func Shell() (string, string) {
	if _, err := exec.LookPath("cmd"); err == nil {
		return "cmd", "/C"
	}
	return "powershell", "-Command"
}

// LookupExecutable finds the full path of an executable in PATH.
func LookupExecutable(name string) (string, error) {
	return exec.LookPath(name)
}
