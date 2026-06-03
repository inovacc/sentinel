package cmd

import (
	"strings"
	"testing"

	"github.com/inovacc/sentinel/internal/fleet"
)

func TestPairingConflict(t *testing.T) {
	tests := []struct {
		name         string
		existing     *fleet.Device
		newFP        string
		wantConflict bool
	}{
		{
			name:         "first pairing (no existing peer)",
			existing:     nil,
			newFP:        "sha256:aaaa",
			wantConflict: false,
		},
		{
			name:         "existing peer without a pinned CA (legacy)",
			existing:     &fleet.Device{DeviceID: "P", CAFingerprint: ""},
			newFP:        "sha256:aaaa",
			wantConflict: false,
		},
		{
			name:         "re-pair with the same CA",
			existing:     &fleet.Device{DeviceID: "P", CAFingerprint: "sha256:aaaa"},
			newFP:        "sha256:aaaa",
			wantConflict: false,
		},
		{
			name:         "known peer presents a DIFFERENT CA (rotation / MITM)",
			existing:     &fleet.Device{DeviceID: "P", CAFingerprint: "sha256:aaaa"},
			newFP:        "sha256:bbbb",
			wantConflict: true,
		},
		{
			name:         "cannot verify (no new fingerprint) does not block",
			existing:     &fleet.Device{DeviceID: "P", CAFingerprint: "sha256:aaaa"},
			newFP:        "",
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflict, msg := pairingConflict(tt.existing, tt.newFP)
			if conflict != tt.wantConflict {
				t.Fatalf("conflict = %v, want %v", conflict, tt.wantConflict)
			}
			if conflict {
				low := strings.ToLower(msg)
				if !strings.Contains(low, "ca") || !strings.Contains(low, "--force") {
					t.Errorf("conflict message should explain the CA change and mention --force, got: %s", msg)
				}
				if !strings.Contains(msg, tt.existing.CAFingerprint) || !strings.Contains(msg, tt.newFP) {
					t.Errorf("conflict message should show expected and received fingerprints, got: %s", msg)
				}
			}
		})
	}
}
