package cmd

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/inovacc/sentinel/internal/fleet"
)

func TestRepairGuard(t *testing.T) {
	pinned := &fleet.Device{DeviceID: "P", CAFingerprint: "sha256:aaaa"}

	tests := []struct {
		name       string
		existing   *fleet.Device
		lookupErr  error
		newFP      string
		force      bool
		wantRefuse bool
	}{
		{"known peer, same CA", pinned, nil, "sha256:aaaa", false, false},
		{"known peer, rotated CA", pinned, nil, "sha256:bbbb", false, true},
		{"known peer, rotated CA, --force", pinned, nil, "sha256:bbbb", true, false},
		{"peer not found (ErrNoRows)", nil, sql.ErrNoRows, "sha256:aaaa", false, false},
		{"trust-store error fails closed", nil, errors.New("database is locked"), "sha256:aaaa", false, true},
		{"trust-store error, --force overrides", nil, errors.New("database is locked"), "sha256:aaaa", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, refuse := repairGuard(tt.existing, tt.lookupErr, tt.newFP, tt.force)
			if refuse != tt.wantRefuse {
				t.Fatalf("refuse = %v, want %v (msg=%q)", refuse, tt.wantRefuse, msg)
			}
			if refuse && msg == "" {
				t.Error("a refusal must carry an explanatory message")
			}
			if refuse && !tt.force && strings.Contains(tt.name, "trust-store") &&
				!strings.Contains(msg, "--force") {
				t.Errorf("trust-store refusal should offer the --force escape hatch, got %q", msg)
			}
		})
	}
}
