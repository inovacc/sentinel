package discovery

import (
	"os"
	"testing"
	"time"
)

func TestNewAdvertiserValidation(t *testing.T) {
	tests := []struct {
		name     string
		deviceID string
		hostname string
		port     int
		wantErr  bool
	}{
		{"valid", "DEVID", "host", 7399, false},
		{"empty device id", "", "host", 7399, true},
		{"empty hostname", "DEVID", "", 7399, true},
		{"zero port", "DEVID", "host", 0, true},
		{"negative port", "DEVID", "host", -1, true},
		{"port too large", "DEVID", "host", 70000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv, err := NewAdvertiser(tt.deviceID, tt.hostname, "v1", tt.port, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (adv=%v)", adv)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if adv == nil {
				t.Fatal("expected non-nil advertiser")
			}
		})
	}
}

// TestNewAdvertiserNilLoggerDefaults ensures a nil logger is tolerated (a nil
// logger would panic on Start otherwise).
func TestNewAdvertiserNilLoggerDefaults(t *testing.T) {
	adv, err := NewAdvertiser("DEVID", "host", "v1", 7399, nil)
	if err != nil {
		t.Fatalf("NewAdvertiser: %v", err)
	}
	if adv.logger == nil {
		t.Fatal("nil logger should fall back to slog.Default()")
	}
}

// TestAdvertiseScanRoundTrip starts an advertiser and confirms a scanner finds
// it. It binds real mDNS multicast, so it is gated behind SENTINEL_TEST_MDNS to
// keep the default `go test` run hermetic (and avoid host firewall prompts).
func TestAdvertiseScanRoundTrip(t *testing.T) {
	if os.Getenv("SENTINEL_TEST_MDNS") == "" {
		t.Skip("set SENTINEL_TEST_MDNS=1 to run the mDNS round-trip (binds multicast)")
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "test-host"
	}
	const devID = "ROUNDTRIPDEVICEID"

	adv, err := NewAdvertiser(devID, hostname, "v-test", 7399, nil)
	if err != nil {
		t.Fatalf("NewAdvertiser: %v", err)
	}
	if err := adv.Start(); err != nil {
		t.Fatalf("advertiser Start: %v", err)
	}
	defer adv.Stop()

	scanner := NewScanner()
	var found bool
	for attempt := 0; attempt < 3 && !found; attempt++ {
		devices, err := scanner.Scan(2 * time.Second)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		for _, d := range devices {
			if d.DeviceID == devID {
				found = true
				if d.Version != "v-test" {
					t.Errorf("discovered version = %q, want %q", d.Version, "v-test")
				}
			}
		}
	}
	if !found {
		t.Fatalf("advertised device %q was not discovered via mDNS scan", devID)
	}
}
