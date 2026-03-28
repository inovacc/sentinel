package session

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newTestManager creates a Manager backed by an in-memory SQLite database.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mgr, err := NewManager(db)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return mgr
}

func TestCreateSession(t *testing.T) {
	tests := []struct {
		name        string
		deviceID    string
		projectName string
		description string
		workingDir  string
		env         map[string]string
	}{
		{
			name:        "basic creation",
			deviceID:    "device-1",
			projectName: "sentinel",
			description: "test session",
			workingDir:  "/tmp/work",
			env:         map[string]string{"FOO": "bar"},
		},
		{
			name:        "empty env",
			deviceID:    "device-2",
			projectName: "other",
			description: "",
			workingDir:  "/home/user",
			env:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newTestManager(t)
			ctx := context.Background()

			s, err := mgr.Create(ctx, tt.deviceID, tt.projectName, tt.description, tt.workingDir, tt.env)
			if err != nil {
				t.Fatalf("create: %v", err)
			}

			if s.ID == "" {
				t.Error("expected non-empty ID")
			}
			if s.DeviceID != tt.deviceID {
				t.Errorf("device_id = %q, want %q", s.DeviceID, tt.deviceID)
			}
			if s.Status != StatusActive {
				t.Errorf("status = %q, want %q", s.Status, StatusActive)
			}
			if s.Context == nil {
				t.Fatal("expected non-nil context")
			}
			if s.Context.WorkingDir != tt.workingDir {
				t.Errorf("working_dir = %q, want %q", s.Context.WorkingDir, tt.workingDir)
			}
			if s.Context.ProjectName != tt.projectName {
				t.Errorf("project_name = %q, want %q", s.Context.ProjectName, tt.projectName)
			}

			// Verify we can retrieve it.
			got, err := mgr.Get(ctx, s.ID)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.ID != s.ID {
				t.Errorf("get ID = %q, want %q", got.ID, s.ID)
			}
		})
	}
}

func TestResumeSession(t *testing.T) {
	tests := []struct {
		name        string
		pauseFirst  bool
		expectError bool
	}{
		{
			name:        "resume paused session",
			pauseFirst:  true,
			expectError: false,
		},
		{
			name:        "resume active session fails",
			pauseFirst:  false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newTestManager(t)
			ctx := context.Background()

			s, err := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", nil)
			if err != nil {
				t.Fatalf("create: %v", err)
			}

			// Add some events and a checkpoint before pausing.
			if err := mgr.AddEvent(ctx, s.ID, "command", []byte("ls -la")); err != nil {
				t.Fatalf("add event: %v", err)
			}

			if tt.pauseFirst {
				if _, err := mgr.Pause(ctx, s.ID, "taking a break"); err != nil {
					t.Fatalf("pause: %v", err)
				}
			}

			resumed, cp, events, err := mgr.Resume(ctx, s.ID)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("resume: %v", err)
			}

			if resumed.Status != StatusActive {
				t.Errorf("status = %q, want %q", resumed.Status, StatusActive)
			}
			if resumed.ResumedAt == nil {
				t.Error("expected resumed_at to be set")
			}
			if cp == nil {
				t.Error("expected checkpoint from paused session")
			}
			if len(events) == 0 {
				t.Error("expected at least one event")
			}
		})
	}
}

func TestPauseSession(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	s, err := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", map[string]string{"KEY": "val"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	cp, err := mgr.Pause(ctx, s.ID, "pause reason")
	if err != nil {
		t.Fatalf("pause: %v", err)
	}

	if cp == nil {
		t.Fatal("expected checkpoint")
	}
	if cp.Description != "pause reason" {
		t.Errorf("checkpoint description = %q, want %q", cp.Description, "pause reason")
	}
	if cp.State == nil {
		t.Fatal("expected checkpoint state")
	}
	if cp.State.WorkingDir != "/tmp" {
		t.Errorf("checkpoint working_dir = %q, want %q", cp.State.WorkingDir, "/tmp")
	}

	// Verify session is paused.
	got, err := mgr.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusPaused {
		t.Errorf("status = %q, want %q", got.Status, StatusPaused)
	}
}

func TestCompleteAndFailSession(t *testing.T) {
	tests := []struct {
		name       string
		action     string
		wantStatus Status
	}{
		{name: "complete", action: "complete", wantStatus: StatusCompleted},
		{name: "fail", action: "fail", wantStatus: StatusFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newTestManager(t)
			ctx := context.Background()

			s, err := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", nil)
			if err != nil {
				t.Fatalf("create: %v", err)
			}

			switch tt.action {
			case "complete":
				err = mgr.Complete(ctx, s.ID)
			case "fail":
				err = mgr.Fail(ctx, s.ID, "something went wrong")
			}
			if err != nil {
				t.Fatalf("%s: %v", tt.action, err)
			}

			got, err := mgr.Get(ctx, s.ID)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if tt.action == "fail" && got.ErrorInfo != "something went wrong" {
				t.Errorf("error_info = %q, want %q", got.ErrorInfo, "something went wrong")
			}
		})
	}
}

func TestListSessions(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	// Create sessions for different devices and statuses.
	s1, _ := mgr.Create(ctx, "device-1", "proj", "d1", "/tmp", nil)
	s2, _ := mgr.Create(ctx, "device-1", "proj", "d2", "/tmp", nil)
	_, _ = mgr.Create(ctx, "device-2", "proj", "d3", "/tmp", nil)

	// Pause s2.
	_, _ = mgr.Pause(ctx, s2.ID, "reason")

	tests := []struct {
		name         string
		deviceID     string
		statusFilter Status
		limit        int
		wantCount    int
	}{
		{name: "all sessions", deviceID: "", statusFilter: "", limit: 0, wantCount: 3},
		{name: "by device", deviceID: "device-1", statusFilter: "", limit: 0, wantCount: 2},
		{name: "by status active", deviceID: "", statusFilter: StatusActive, limit: 0, wantCount: 2},
		{name: "by device and status", deviceID: "device-1", statusFilter: StatusActive, limit: 0, wantCount: 1},
		{name: "with limit", deviceID: "", statusFilter: "", limit: 2, wantCount: 2},
	}

	_ = s1 // used above

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := mgr.List(ctx, tt.deviceID, tt.statusFilter, tt.limit)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(sessions) != tt.wantCount {
				t.Errorf("got %d sessions, want %d", len(sessions), tt.wantCount)
			}
		})
	}
}

func TestDestroySession(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	s, _ := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", nil)
	_ = mgr.AddEvent(ctx, s.ID, "command", []byte("echo hello"))
	_, _ = mgr.CreateCheckpoint(ctx, s.ID, "cp1", s.Context)

	if err := mgr.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	// Session should be gone.
	_, err := mgr.Get(ctx, s.ID)
	if err == nil {
		t.Error("expected error after destroy, got nil")
	}
}

func TestRecoverInterrupted(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	// Create several active sessions.
	_, _ = mgr.Create(ctx, "device-1", "proj", "d1", "/tmp", nil)
	_, _ = mgr.Create(ctx, "device-2", "proj", "d2", "/tmp", nil)
	s3, _ := mgr.Create(ctx, "device-3", "proj", "d3", "/tmp", nil)
	// Complete one so it shouldn't be affected.
	_ = mgr.Complete(ctx, s3.ID)

	count, err := mgr.RecoverInterrupted(ctx)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if count != 2 {
		t.Errorf("recovered %d, want 2", count)
	}

	// Verify all active are now interrupted.
	sessions, _ := mgr.List(ctx, "", StatusInterrupted, 0)
	if len(sessions) != 2 {
		t.Errorf("interrupted count = %d, want 2", len(sessions))
	}

	// Completed session should still be completed.
	got, _ := mgr.Get(ctx, s3.ID)
	if got.Status != StatusCompleted {
		t.Errorf("completed session status = %q, want %q", got.Status, StatusCompleted)
	}
}

func TestCheckStale(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	s, _ := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", nil)

	// Manually set the heartbeat to the past.
	mgr.mu.Lock()
	mgr.heartbeats[s.ID] = time.Now().Add(-10 * time.Minute)
	mgr.mu.Unlock()

	count, err := mgr.CheckStale(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("check stale: %v", err)
	}
	if count != 1 {
		t.Errorf("stale count = %d, want 1", count)
	}

	got, _ := mgr.Get(ctx, s.ID)
	if got.Status != StatusInterrupted {
		t.Errorf("status = %q, want %q", got.Status, StatusInterrupted)
	}
}

func TestAddEvent(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	s, _ := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", nil)

	// Add multiple events and verify sequence numbering.
	for i := 0; i < 5; i++ {
		if err := mgr.AddEvent(ctx, s.ID, "command", []byte("cmd")); err != nil {
			t.Fatalf("add event %d: %v", i, err)
		}
	}

	events, err := selectRecentEvents(mgr.db, s.ID, 10)
	if err != nil {
		t.Fatalf("select events: %v", err)
	}

	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}

	// Verify sequences are 1, 2, 3, 4, 5 (ascending order).
	for i, e := range events {
		want := i + 1
		if e.Sequence != want {
			t.Errorf("event %d sequence = %d, want %d", i, e.Sequence, want)
		}
	}
}

func TestCreateCheckpointRoundTrip(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	s, _ := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", nil)

	state := &SessionContext{
		WorkingDir:   "/home/user/project",
		Env:          map[string]string{"GOPATH": "/go", "HOME": "/home/user"},
		LastCommand:  "go test ./...",
		LastOutput:   "PASS",
		LastExitCode: 0,
		ProjectName:  "sentinel",
	}

	cp, err := mgr.CreateCheckpoint(ctx, s.ID, "before deploy", state)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}

	if cp.State == nil {
		t.Fatal("expected non-nil state")
	}
	if cp.State.WorkingDir != state.WorkingDir {
		t.Errorf("working_dir = %q, want %q", cp.State.WorkingDir, state.WorkingDir)
	}
	if cp.State.LastCommand != state.LastCommand {
		t.Errorf("last_command = %q, want %q", cp.State.LastCommand, state.LastCommand)
	}
	if cp.State.Env["GOPATH"] != "/go" {
		t.Errorf("env GOPATH = %q, want %q", cp.State.Env["GOPATH"], "/go")
	}

	// Retrieve the checkpoint via the store function and verify round-trip.
	got, err := selectLastCheckpoint(mgr.db, s.ID)
	if err != nil {
		t.Fatalf("select checkpoint: %v", err)
	}
	if got.State.LastOutput != "PASS" {
		t.Errorf("last_output = %q, want %q", got.State.LastOutput, "PASS")
	}
	if got.Description != "before deploy" {
		t.Errorf("description = %q, want %q", got.Description, "before deploy")
	}
}

func TestResumeNonExistent(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	_, _, _, err := mgr.Resume(ctx, "non-existent-id")
	if err == nil {
		t.Error("expected error for non-existent session, got nil")
	}
}

func TestResumeCompletedSession(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	s, _ := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", nil)
	_ = mgr.Complete(ctx, s.ID)

	_, _, _, err := mgr.Resume(ctx, s.ID)
	if err == nil {
		t.Error("expected error for completed session, got nil")
	}
}

func TestPauseNonActiveSession(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	s, _ := mgr.Create(ctx, "device-1", "proj", "desc", "/tmp", nil)
	_ = mgr.Complete(ctx, s.ID)

	_, err := mgr.Pause(ctx, s.ID, "reason")
	if err == nil {
		t.Error("expected error pausing completed session, got nil")
	}
}
