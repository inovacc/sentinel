//go:build windows

package capture

import (
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
)

// Screenshot captures the screen using PowerShell and .NET on Windows.
func Screenshot(display int, quality int) ([]byte, string, error) {
	tmpDir := os.TempDir()
	outPath := filepath.Join(tmpDir, "sentinel-screenshot.png")

	// Use PowerShell with System.Windows.Forms.Screen and System.Drawing.
	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$screens = [System.Windows.Forms.Screen]::AllScreens
$idx = %d
if ($idx -ge $screens.Length) {
    Write-Error "Display index $idx out of range (available: $($screens.Length))"
    exit 1
}

$screen = $screens[$idx]
$bounds = $screen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$graphics.Dispose()

$outPath = '%s'
`, display, outPath)

	if quality > 0 && quality < 100 {
		// Save as JPEG with quality setting.
		outPath = filepath.Join(tmpDir, "sentinel-screenshot.jpg")
		psScript = fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$screens = [System.Windows.Forms.Screen]::AllScreens
$idx = %d
if ($idx -ge $screens.Length) {
    Write-Error "Display index $idx out of range (available: $($screens.Length))"
    exit 1
}

$screen = $screens[$idx]
$bounds = $screen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$graphics.Dispose()

$codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
$encoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
$encoderParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [int64]%d)
$bitmap.Save('%s', $codec, $encoderParams)
$bitmap.Dispose()
`, display, quality, outPath)
	} else {
		psScript += fmt.Sprintf(`$bitmap.Save('%s', [System.Drawing.Imaging.ImageFormat]::Png)
$bitmap.Dispose()
`, outPath)
	}

	cmd := osexec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("capture: powershell screenshot failed: %w\noutput: %s", err, string(output))
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, "", fmt.Errorf("capture: read screenshot file: %w", err)
	}

	// Clean up temp file.
	_ = os.Remove(outPath)

	format := "png"
	if quality > 0 && quality < 100 {
		format = "jpeg"
	}

	return data, format, nil
}

