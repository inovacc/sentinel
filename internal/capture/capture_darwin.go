//go:build darwin

package capture

import (
	"fmt"
	"os"
	osexec "os/exec"
	"strconv"
)

// Screenshot captures the screen using macOS screencapture.
func Screenshot(display int, quality int) ([]byte, string, error) {
	if _, err := osexec.LookPath("screencapture"); err != nil {
		return nil, "", fmt.Errorf("capture: screencapture not found; ensure macOS command-line tools are available")
	}

	outPath := "/tmp/sentinel-screenshot.png"
	format := "png"

	args := []string{"-x"} // silent, no sound

	// Select display.
	if display > 0 {
		args = append(args, "-D", strconv.Itoa(display+1)) // macOS uses 1-based display indices
	}

	// JPEG quality.
	if quality > 0 && quality < 100 {
		outPath = "/tmp/sentinel-screenshot.jpg"
		format = "jpeg"
		args = append(args, "-t", "jpg")
	}

	args = append(args, outPath)

	cmd := osexec.Command("screencapture", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("capture: screencapture failed: %w\noutput: %s", err, string(output))
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, "", fmt.Errorf("capture: read screenshot file: %w", err)
	}

	_ = os.Remove(outPath)

	return data, format, nil
}
