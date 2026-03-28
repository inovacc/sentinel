//go:build linux

package capture

import (
	"fmt"
	"os"
	osexec "os/exec"
)

// Screenshot captures the screen using available Linux screenshot tools.
// Tries in order: import (ImageMagick), gnome-screenshot, scrot.
func Screenshot(display int, quality int) ([]byte, string, error) {
	outPath := "/tmp/sentinel-screenshot.png"
	format := "png"

	// Try ImageMagick import first.
	if path, err := osexec.LookPath("import"); err == nil {
		_ = path
		args := []string{"-window", "root"}
		if quality > 0 && quality < 100 {
			outPath = "/tmp/sentinel-screenshot.jpg"
			format = "jpeg"
			args = append(args, "-quality", fmt.Sprintf("%d", quality))
		}
		args = append(args, outPath)

		cmd := osexec.Command("import", args...)
		if display > 0 {
			cmd.Env = append(os.Environ(), fmt.Sprintf("DISPLAY=:%d", display))
		}

		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, "", fmt.Errorf("capture: import (ImageMagick) failed: %w\noutput: %s", err, string(output))
		}

		return readAndClean(outPath, format)
	}

	// Try gnome-screenshot.
	if path, err := osexec.LookPath("gnome-screenshot"); err == nil {
		_ = path
		args := []string{"-f", outPath}
		if display > 0 {
			args = append(args, "-d", fmt.Sprintf("%d", display))
		}

		cmd := osexec.Command("gnome-screenshot", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, "", fmt.Errorf("capture: gnome-screenshot failed: %w\noutput: %s", err, string(output))
		}

		return readAndClean(outPath, format)
	}

	// Try scrot.
	if path, err := osexec.LookPath("scrot"); err == nil {
		_ = path
		args := []string{outPath}
		if quality > 0 && quality < 100 {
			outPath = "/tmp/sentinel-screenshot.jpg"
			format = "jpeg"
			args = []string{"--quality", fmt.Sprintf("%d", quality), outPath}
		}

		cmd := osexec.Command("scrot", args...)
		if display > 0 {
			cmd.Env = append(os.Environ(), fmt.Sprintf("DISPLAY=:%d", display))
		}

		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, "", fmt.Errorf("capture: scrot failed: %w\noutput: %s", err, string(output))
		}

		return readAndClean(outPath, format)
	}

	return nil, "", fmt.Errorf("capture: no screenshot tool found; install one of: imagemagick (import), gnome-screenshot, or scrot")
}

func readAndClean(path, format string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("capture: read screenshot file: %w", err)
	}
	_ = os.Remove(path)
	return data, format, nil
}
