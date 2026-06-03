// internal/confine/confine_test.go
package confine

import "testing"

func TestDecide(t *testing.T) {
	tests := []struct {
		name                 string
		supported            bool
		applyErr             error
		wantRefuse, wantWarn bool
	}{
		{"supported, applied", true, nil, false, false},
		{"supported, apply error -> refuse", true, errTest, true, false},
		{"unsupported, no error -> warn", false, nil, false, true},
		{"unsupported, error -> warn (never refuse)", false, errTest, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refuse, warn := decide(tt.supported, tt.applyErr)
			if refuse != tt.wantRefuse || warn != tt.wantWarn {
				t.Fatalf("decide(%v,%v) = (%v,%v), want (%v,%v)",
					tt.supported, tt.applyErr, refuse, warn, tt.wantRefuse, tt.wantWarn)
			}
		})
	}
}

func TestNoopConfinerUnsupported(t *testing.T) {
	c, err := New(Config{Enabled: true}, nil) // on non-windows this is the no-op
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.Supported() {
		t.Skip("real confiner on this platform; covered by the windows test")
	}
	if err := c.Prepare(nil); err != nil {
		t.Errorf("noop Prepare should not error: %v", err)
	}
	if err := c.Confine(nil); err != nil {
		t.Errorf("noop Confine should not error: %v", err)
	}
}

func TestDisabledConfigYieldsNoop(t *testing.T) {
	c, err := New(Config{Enabled: false}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.Supported() {
		t.Error("a disabled confiner must report Supported()==false")
	}
}

var errTest = &testErr{}

type testErr struct{}

func (*testErr) Error() string { return "test error" }
