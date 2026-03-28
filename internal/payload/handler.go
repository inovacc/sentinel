// Package payload implements a registry of structured JSON action handlers.
package payload

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
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
