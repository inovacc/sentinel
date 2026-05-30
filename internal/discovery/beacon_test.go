package discovery

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeAdv is a test double for advertiserControl that counts Start/Stop calls.
type fakeAdv struct {
	mu       sync.Mutex
	starts   int
	stops    int
	startErr error
}

func (f *fakeAdv) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	return f.startErr
}

func (f *fakeAdv) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
}

func (f *fakeAdv) snapshot() (starts, stops int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.stops
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestBeaconAdvertisesOnTriggerThenClosesAfterWindow(t *testing.T) {
	f := &fakeAdv{}
	b := NewBeacon(f, 60*time.Millisecond, nil)
	defer b.Close()

	b.Trigger()
	waitFor(t, func() bool { s, _ := f.snapshot(); return s >= 1 }, time.Second, "advertising to start")
	waitFor(t, func() bool { _, st := f.snapshot(); return st >= 1 }, time.Second, "window to close")

	starts, stops := f.snapshot()
	if starts != 1 {
		t.Errorf("started %d times, want 1", starts)
	}
	if stops != 1 {
		t.Errorf("stopped %d times, want 1", stops)
	}
}

func TestBeaconContinuousTriggersKeepWindowOpen(t *testing.T) {
	f := &fakeAdv{}
	// Window is far larger than the trigger interval so the assertion that the
	// window stays open is robust to scheduler delays under load.
	window := 300 * time.Millisecond
	b := NewBeacon(f, window, nil)
	defer b.Close()

	// Keep triggering well within the window for ~240ms.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 8 {
			b.Trigger()
			time.Sleep(30 * time.Millisecond)
		}
	}()

	waitFor(t, func() bool { s, _ := f.snapshot(); return s >= 1 }, time.Second, "advertising to start")
	<-done

	// Throughout continuous triggering it must not have stopped or restarted.
	starts, stops := f.snapshot()
	if starts != 1 {
		t.Errorf("started %d times during continuous triggering, want 1 (no restart)", starts)
	}
	if stops != 0 {
		t.Errorf("stopped %d times during continuous triggering, want 0", stops)
	}

	// Once triggers stop, the window should close on its own.
	waitFor(t, func() bool { _, st := f.snapshot(); return st >= 1 }, time.Second, "window to close after triggers stop")
}

func TestBeaconReAdvertisesAfterWindowCloses(t *testing.T) {
	f := &fakeAdv{}
	b := NewBeacon(f, 50*time.Millisecond, nil)
	defer b.Close()

	b.Trigger()
	waitFor(t, func() bool { _, st := f.snapshot(); return st >= 1 }, time.Second, "first window to close")

	// A new trigger after the window closed must re-open advertising.
	b.Trigger()
	waitFor(t, func() bool { s, _ := f.snapshot(); return s >= 2 }, time.Second, "advertising to restart")
}

func TestBeaconCloseStopsAdvertising(t *testing.T) {
	f := &fakeAdv{}
	b := NewBeacon(f, 10*time.Second, nil) // long window; only Close should stop it
	b.Trigger()
	waitFor(t, func() bool { s, _ := f.snapshot(); return s >= 1 }, time.Second, "advertising to start")

	b.Close() // blocks until torn down
	_, stops := f.snapshot()
	if stops != 1 {
		t.Errorf("stopped %d times after Close, want 1", stops)
	}
	b.Close() // idempotent, must not panic
}

func TestBeaconStartErrorIsRecoverable(t *testing.T) {
	f := &fakeAdv{startErr: errors.New("bind failed")}
	b := NewBeacon(f, 10*time.Second, nil)
	defer b.Close()

	b.Trigger()
	waitFor(t, func() bool { s, _ := f.snapshot(); return s >= 1 }, time.Second, "first (failing) start attempt")

	// A failed Start must not count as advertising, so a later Trigger retries.
	f.mu.Lock()
	f.startErr = nil
	f.mu.Unlock()

	b.Trigger()
	waitFor(t, func() bool { s, _ := f.snapshot(); return s >= 2 }, time.Second, "retry after error")
}
