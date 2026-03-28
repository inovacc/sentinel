// Package payload implements a registry of structured JSON action handlers.
package payload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/inovacc/sentinel/internal/docker"
)

// Handler processes a JSON payload for a given action and returns a JSON response.
type Handler func(ctx context.Context, action string, payload json.RawMessage) (json.RawMessage, error)

// Registry manages action handlers.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry creates a registry with built-in actions pre-registered.
func NewRegistry() *Registry {
	r := &Registry{
		handlers: make(map[string]Handler),
	}
	r.registerBuiltins()
	return r
}

// Register adds a handler for the given action. Overwrites if exists.
func (r *Registry) Register(action string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[action] = h
}

// Handle dispatches a payload to the registered handler for the given action.
func (r *Registry) Handle(ctx context.Context, action string, payload json.RawMessage) (json.RawMessage, error) {
	r.mu.RLock()
	h, ok := r.handlers[action]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown action: %q", action)
	}

	return h(ctx, action, payload)
}

// Actions returns a list of registered action names.
func (r *Registry) Actions() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	actions := make([]string, 0, len(r.handlers))
	for a := range r.handlers {
		actions = append(actions, a)
	}
	return actions
}

func (r *Registry) registerBuiltins() {
	r.Register("ping", handlePing)
	r.Register("sysinfo", handleSysinfo)
	r.Register("env.get", handleEnvGet)
	r.Register("actions", handleActions(r))
	r.Register("echo", handleEcho)

	// Docker actions.
	r.Register("docker.available", handleDockerAvailable)
	r.Register("docker.create", handleDockerCreate)
	r.Register("docker.exec", handleDockerExec)
	r.Register("docker.stop", handleDockerStop)
	r.Register("docker.remove", handleDockerRemove)
	r.Register("docker.list", handleDockerList)

	// Auto-update actions.
	r.Register("update.check", handleUpdateCheck)
	r.Register("update.apply", handleUpdateApply)
}

// --- Built-in action handlers ---

func handlePing(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	resp := struct {
		Pong      bool   `json:"pong"`
		Timestamp string `json:"timestamp"`
	}{
		Pong:      true,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	return json.Marshal(resp)
}

func handleSysinfo(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	hostname, _ := os.Hostname()
	resp := struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
		Arch     string `json:"arch"`
		NumCPU   int    `json:"num_cpu"`
		GoVer    string `json:"go_version"`
		PID      int    `json:"pid"`
	}{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		NumCPU:   runtime.NumCPU(),
		GoVer:    runtime.Version(),
		PID:      os.Getpid(),
	}
	return json.Marshal(resp)
}

func handleEnvGet(_ context.Context, _ string, payload json.RawMessage) (json.RawMessage, error) {
	var req struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("env.get: invalid payload: %w", err)
	}
	if len(req.Keys) == 0 {
		return nil, fmt.Errorf("env.get: 'keys' array is required")
	}

	result := make(map[string]string, len(req.Keys))
	for _, k := range req.Keys {
		result[k] = os.Getenv(k)
	}
	return json.Marshal(result)
}

func handleActions(r *Registry) Handler {
	return func(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(struct {
			Actions []string `json:"actions"`
		}{
			Actions: r.Actions(),
		})
	}
}

func handleEcho(_ context.Context, _ string, payload json.RawMessage) (json.RawMessage, error) {
	// Echo back whatever was sent.
	if len(payload) == 0 {
		return json.Marshal(struct {
			Echo string `json:"echo"`
		}{Echo: "empty"})
	}
	return payload, nil
}

// --- Docker action handlers ---

func getDockerManager() (*docker.Manager, error) {
	return docker.NewManager()
}

func handleDockerAvailable(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	mgr, err := getDockerManager()
	if err != nil {
		return nil, fmt.Errorf("docker.available: %w", err)
	}
	return json.Marshal(struct {
		Available bool `json:"available"`
	}{Available: mgr.Available()})
}

func handleDockerCreate(ctx context.Context, _ string, payload json.RawMessage) (json.RawMessage, error) {
	var req struct {
		Image  string            `json:"image"`
		Name   string            `json:"name"`
		Mounts []docker.Mount    `json:"mounts"`
		Env    map[string]string `json:"env"`
		Limits docker.ResourceLimits `json:"limits"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("docker.create: invalid payload: %w", err)
	}
	if req.Image == "" {
		return nil, fmt.Errorf("docker.create: 'image' is required")
	}

	mgr, err := getDockerManager()
	if err != nil {
		return nil, fmt.Errorf("docker.create: %w", err)
	}
	if !mgr.Available() {
		return nil, fmt.Errorf("docker.create: docker is not available")
	}

	containerID, err := mgr.CreateContainer(ctx, req.Image, req.Name, req.Mounts, req.Env, req.Limits)
	if err != nil {
		return nil, fmt.Errorf("docker.create: %w", err)
	}

	// Auto-start the container.
	if err := mgr.StartContainer(ctx, containerID); err != nil {
		return nil, fmt.Errorf("docker.create: start: %w", err)
	}

	return json.Marshal(struct {
		ContainerID string `json:"container_id"`
		Started     bool   `json:"started"`
	}{ContainerID: containerID, Started: true})
}

func handleDockerExec(ctx context.Context, _ string, payload json.RawMessage) (json.RawMessage, error) {
	var req struct {
		ContainerID string   `json:"container_id"`
		Command     string   `json:"command"`
		Args        []string `json:"args"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("docker.exec: invalid payload: %w", err)
	}
	if req.ContainerID == "" || req.Command == "" {
		return nil, fmt.Errorf("docker.exec: 'container_id' and 'command' are required")
	}

	mgr, err := getDockerManager()
	if err != nil {
		return nil, fmt.Errorf("docker.exec: %w", err)
	}

	result, err := mgr.ExecInContainer(ctx, req.ContainerID, req.Command, req.Args)
	if err != nil {
		return nil, fmt.Errorf("docker.exec: %w", err)
	}
	return json.Marshal(result)
}

func handleDockerStop(ctx context.Context, _ string, payload json.RawMessage) (json.RawMessage, error) {
	var req struct {
		ContainerID string `json:"container_id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("docker.stop: invalid payload: %w", err)
	}
	if req.ContainerID == "" {
		return nil, fmt.Errorf("docker.stop: 'container_id' is required")
	}

	mgr, err := getDockerManager()
	if err != nil {
		return nil, fmt.Errorf("docker.stop: %w", err)
	}

	if err := mgr.StopContainer(ctx, req.ContainerID); err != nil {
		return nil, fmt.Errorf("docker.stop: %w", err)
	}
	return json.Marshal(struct {
		Stopped bool `json:"stopped"`
	}{Stopped: true})
}

func handleDockerRemove(ctx context.Context, _ string, payload json.RawMessage) (json.RawMessage, error) {
	var req struct {
		ContainerID string `json:"container_id"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("docker.remove: invalid payload: %w", err)
	}
	if req.ContainerID == "" {
		return nil, fmt.Errorf("docker.remove: 'container_id' is required")
	}

	mgr, err := getDockerManager()
	if err != nil {
		return nil, fmt.Errorf("docker.remove: %w", err)
	}

	if err := mgr.RemoveContainer(ctx, req.ContainerID); err != nil {
		return nil, fmt.Errorf("docker.remove: %w", err)
	}
	return json.Marshal(struct {
		Removed bool `json:"removed"`
	}{Removed: true})
}

func handleDockerList(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	mgr, err := getDockerManager()
	if err != nil {
		return nil, fmt.Errorf("docker.list: %w", err)
	}
	if !mgr.Available() {
		return nil, fmt.Errorf("docker.list: docker is not available")
	}

	containers, err := mgr.ListContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("docker.list: %w", err)
	}
	return json.Marshal(struct {
		Containers []docker.ContainerInfo `json:"containers"`
	}{Containers: containers})
}

// --- Auto-update action handlers ---

// version is set via ldflags at build time: -ldflags "-X github.com/inovacc/sentinel/internal/payload.version=v1.0.0"
var version = "dev"

func handleUpdateCheck(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	// Query the latest module version without installing.
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("go", "list", "-m", "-json", "github.com/inovacc/sentinel@latest")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("update.check: %s: %w", strings.TrimSpace(stderr.String()), err)
	}

	var modInfo struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &modInfo); err != nil {
		return nil, fmt.Errorf("update.check: parse module info: %w", err)
	}

	updateAvailable := modInfo.Version != version && version != "dev"

	return json.Marshal(struct {
		CurrentVersion  string `json:"current_version"`
		LatestVersion   string `json:"latest_version"`
		UpdateAvailable bool   `json:"update_available"`
	}{
		CurrentVersion:  version,
		LatestVersion:   modInfo.Version,
		UpdateAvailable: updateAvailable,
	})
}

func handleUpdateApply(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("go", "install", "github.com/inovacc/sentinel@latest")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("update.apply: %s: %w", strings.TrimSpace(stderr.String()), err)
	}

	return json.Marshal(struct {
		Updated bool   `json:"updated"`
		Output  string `json:"output"`
	}{
		Updated: true,
		Output:  strings.TrimSpace(stdout.String() + "\n" + stderr.String()),
	})
}
