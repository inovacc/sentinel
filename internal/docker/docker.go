// Package docker manages Docker container lifecycle via the Docker CLI.
package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Manager handles Docker container lifecycle for test execution.
type Manager struct {
	available bool // whether Docker is accessible
}

// Mount describes a bind mount from host to container.
type Mount struct {
	Source string // host path
	Target string // container path
}

// ResourceLimits constrains container resource usage.
type ResourceLimits struct {
	CPUs   string // e.g. "2"
	Memory string // e.g. "512m"
}

// ExecResult holds the output of a command executed inside a container.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// ContainerInfo describes a running sentinel container.
type ContainerInfo struct {
	ID     string
	Name   string
	Image  string
	Status string
}

// NewManager creates a Manager and checks whether the docker CLI is accessible.
func NewManager() (*Manager, error) {
	m := &Manager{}
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	if err := cmd.Run(); err != nil {
		m.available = false
		return m, nil
	}
	m.available = true
	return m, nil
}

// Available reports whether the Docker daemon is reachable.
func (m *Manager) Available() bool {
	return m.available
}

// CreateContainer creates a container with the given configuration.
// All sentinel-managed containers receive the label sentinel=true.
func (m *Manager) CreateContainer(ctx context.Context, image, name string, mounts []Mount, env map[string]string, limits ResourceLimits) (string, error) {
	args := []string{"create", "--label", "sentinel=true"}

	if name != "" {
		args = append(args, "--name", name)
	}
	for _, mt := range mounts {
		args = append(args, "-v", mt.Source+":"+mt.Target)
	}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	if limits.CPUs != "" {
		args = append(args, "--cpus", limits.CPUs)
	}
	if limits.Memory != "" {
		args = append(args, "--memory", limits.Memory)
	}
	args = append(args, image)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker create: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// StartContainer starts a previously created container.
func (m *Manager) StartContainer(ctx context.Context, containerID string) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", "start", containerID)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker start: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return nil
}

// ExecInContainer runs a command inside a running container and returns the result.
func (m *Manager) ExecInContainer(ctx context.Context, containerID, command string, args []string) (*ExecResult, error) {
	execArgs := []string{"exec", containerID, command}
	execArgs = append(execArgs, args...)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", execArgs...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &ExecResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("docker exec: %w", err)
		}
	}
	return result, nil
}

// StreamLogs follows container logs and invokes the callback for each line.
// The stream parameter passed to onOutput is "stdout".
func (m *Manager) StreamLogs(ctx context.Context, containerID string, onOutput func(string, []byte)) error {
	cmd := exec.CommandContext(ctx, "docker", "logs", "-f", containerID)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("docker logs: stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("docker logs: start: %w", err)
	}

	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		onOutput("stdout", scanner.Bytes())
	}

	if err := cmd.Wait(); err != nil {
		// Context cancellation is expected.
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("docker logs: %w", err)
	}
	return nil
}

// StopContainer stops a running container.
func (m *Manager) StopContainer(ctx context.Context, containerID string) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", "stop", containerID)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker stop: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return nil
}

// RemoveContainer forcefully removes a container.
func (m *Manager) RemoveContainer(ctx context.Context, containerID string) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", containerID)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker rm: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return nil
}

// ListContainers returns all containers with the sentinel=true label.
func (m *Manager) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a",
		"--filter", "label=sentinel=true",
		"--format", "{{json .}}",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker ps: %s: %w", strings.TrimSpace(stderr.String()), err)
	}

	var containers []ContainerInfo
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var raw struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			Image  string `json:"Image"`
			Status string `json:"Status"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		containers = append(containers, ContainerInfo{
			ID:     raw.ID,
			Name:   raw.Names,
			Image:  raw.Image,
			Status: raw.Status,
		})
	}
	return containers, nil
}
