package payload

import (
	"context"
	"encoding/json"
	"testing"
)

func TestPing(t *testing.T) {
	r := NewRegistry()
	resp, err := r.Handle(context.Background(), "ping", nil)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}

	var result struct {
		Pong      bool   `json:"pong"`
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !result.Pong {
		t.Error("expected pong=true")
	}
	if result.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestSysinfo(t *testing.T) {
	r := NewRegistry()
	resp, err := r.Handle(context.Background(), "sysinfo", nil)
	if err != nil {
		t.Fatalf("sysinfo: %v", err)
	}

	var result struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
		Arch     string `json:"arch"`
		NumCPU   int    `json:"num_cpu"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.OS == "" {
		t.Error("expected non-empty OS")
	}
	if result.NumCPU == 0 {
		t.Error("expected non-zero NumCPU")
	}
}

func TestEnvGet(t *testing.T) {
	r := NewRegistry()
	t.Setenv("SENTINEL_TEST_VAR", "hello123")

	payload, _ := json.Marshal(struct {
		Keys []string `json:"keys"`
	}{Keys: []string{"SENTINEL_TEST_VAR", "NONEXISTENT"}})

	resp, err := r.Handle(context.Background(), "env.get", payload)
	if err != nil {
		t.Fatalf("env.get: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["SENTINEL_TEST_VAR"] != "hello123" {
		t.Errorf("expected hello123, got %s", result["SENTINEL_TEST_VAR"])
	}
	if result["NONEXISTENT"] != "" {
		t.Errorf("expected empty, got %s", result["NONEXISTENT"])
	}
}

func TestEnvGet_NoKeys(t *testing.T) {
	r := NewRegistry()
	payload, _ := json.Marshal(struct{ Keys []string }{})
	_, err := r.Handle(context.Background(), "env.get", payload)
	if err == nil {
		t.Error("expected error for empty keys")
	}
}

func TestEcho(t *testing.T) {
	r := NewRegistry()
	input, _ := json.Marshal(map[string]string{"msg": "hello"})

	resp, err := r.Handle(context.Background(), "echo", input)
	if err != nil {
		t.Fatalf("echo: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["msg"] != "hello" {
		t.Errorf("expected hello, got %s", result["msg"])
	}
}

func TestActions(t *testing.T) {
	r := NewRegistry()
	resp, err := r.Handle(context.Background(), "actions", nil)
	if err != nil {
		t.Fatalf("actions: %v", err)
	}

	var result struct {
		Actions []string `json:"actions"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(result.Actions) < 5 {
		t.Errorf("expected at least 5 actions, got %d", len(result.Actions))
	}
}

func TestUnknownAction(t *testing.T) {
	r := NewRegistry()
	_, err := r.Handle(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestCustomHandler(t *testing.T) {
	r := NewRegistry()
	r.Register("custom", func(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(map[string]string{"custom": "works"})
	})

	resp, err := r.Handle(context.Background(), "custom", nil)
	if err != nil {
		t.Fatalf("custom: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["custom"] != "works" {
		t.Errorf("expected works, got %s", result["custom"])
	}
}
