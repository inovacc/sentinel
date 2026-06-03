//go:build windows

package confine

import (
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsConfiner struct {
	cfg    Config
	logger *slog.Logger
	token  windows.Token  // restricted primary token (Task 4); 0 until then
	job    windows.Handle // job object
}

func newConfiner(cfg Config, logger *slog.Logger) (Confiner, error) {
	job, err := newJobObject(cfg)
	if err != nil {
		return nil, fmt.Errorf("confine: job object: %w", err)
	}
	return &windowsConfiner{cfg: cfg, logger: logger, job: job}, nil
}

func (c *windowsConfiner) Supported() bool { return true }

func (c *windowsConfiner) Prepare(cmd *osexec.Cmd) error {
	// Token is wired in Task 4; nothing required here yet.
	_ = cmd
	return nil
}

func (c *windowsConfiner) Confine(p *os.Process) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return fmt.Errorf("confine: open process: %w", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.AssignProcessToJobObject(c.job, h); err != nil {
		return fmt.Errorf("confine: assign to job: %w", err)
	}
	return nil
}

func (c *windowsConfiner) Close() error {
	_ = windows.CloseHandle(c.job) // KILL_ON_JOB_CLOSE terminates remaining children
	if c.token != 0 {
		_ = c.token.Close()
	}
	return nil
}

func newJobObject(cfg Config) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if cfg.MaxProcesses > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = cfg.MaxProcesses
	}
	if cfg.MaxMemoryMB > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = uintptr(cfg.MaxMemoryMB) * 1024 * 1024
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}

	if cfg.CPUPercent > 0 && cfg.CPUPercent < 100 {
		if err := setCPURate(job, cfg.CPUPercent); err != nil {
			_ = windows.CloseHandle(job)
			return 0, err
		}
	}
	return job, nil
}

// jobObjectCPURateControlInformation mirrors the Win32 struct (not wrapped in
// x/sys/windows v0.45). ControlFlags ENABLE(0x1)|HARD_CAP(0x4); Value is the cap
// in 1/100 of one percent (e.g. 80% -> 8000).
type jobObjectCPURateControlInformation struct {
	ControlFlags uint32
	Value        uint32
}

const (
	cpuRateControlEnable  = 0x1
	cpuRateControlHardCap = 0x4
)

func setCPURate(job windows.Handle, pct uint32) error {
	info := jobObjectCPURateControlInformation{
		ControlFlags: cpuRateControlEnable | cpuRateControlHardCap,
		Value:        pct * 100,
	}
	_, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	return err
}
