package client

import (
	"strings"
	"testing"
)

func TestLooksLikeTarget(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"NTRF5R2X-FUVA2UHT-LEV65UAV-AZ2IM5DZ-WY7GD2PH-OESJD5FD-FSXG2FWZ-UEQU", true}, // device id
		{"192.168.1.5:7400", true}, // host:port
		{"127.0.0.1:7399", true},
		{"myserver:7400", true},
		{"go", false},      // command
		{"git", false},     // command
		{"npm:run", false}, // non-numeric port -> not a target
		{"/some/path", false},
		{".", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := LooksLikeTarget(tt.in); got != tt.want {
			t.Errorf("LooksLikeTarget(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantTarget string
		wantRest   []string
	}{
		{"command only", []string{"go", "version"}, "", []string{"go", "version"}},
		{"address then command", []string{"192.168.1.5:7400", "go", "version"}, "192.168.1.5:7400", []string{"go", "version"}},
		{"empty", nil, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, rest := SplitTarget(tt.args)
			if target != tt.wantTarget {
				t.Errorf("target = %q, want %q", target, tt.wantTarget)
			}
			if strings.Join(rest, " ") != strings.Join(tt.wantRest, " ") {
				t.Errorf("rest = %v, want %v", rest, tt.wantRest)
			}
		})
	}
}

func TestResolveAddress(t *testing.T) {
	// Explicit address passes through.
	if got, err := ResolveAddress("10.0.0.4:7400"); err != nil || got != "10.0.0.4:7400" {
		t.Errorf("ResolveAddress(addr) = (%q, %v), want (10.0.0.4:7400, nil)", got, err)
	}
	// Empty target resolves to the local loopback daemon.
	got, err := ResolveAddress("")
	if err != nil {
		t.Fatalf("ResolveAddress(\"\"): %v", err)
	}
	if !strings.HasPrefix(got, "127.0.0.1:") {
		t.Errorf("local address = %q, want 127.0.0.1:<port>", got)
	}
}
