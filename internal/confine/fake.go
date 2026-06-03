// internal/confine/fake.go

package confine

import (
	"os"
	osexec "os/exec"
)

// Fake is a test Confiner whose behavior is fully controllable. It records calls
// so consumers can assert the spawn path invokes Prepare/Confine.
type Fake struct {
	SupportedVal bool
	PrepareErr   error
	ConfineErr   error
	Prepared     int
	Confined     int
}

func (f *Fake) Prepare(*osexec.Cmd) error { f.Prepared++; return f.PrepareErr }
func (f *Fake) Confine(*os.Process) error { f.Confined++; return f.ConfineErr }
func (f *Fake) Supported() bool           { return f.SupportedVal }
func (f *Fake) Close() error              { return nil }
