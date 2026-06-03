package cmd

import (
	"testing"

	"github.com/inovacc/sentinel/pkg/transport"
)

// The bootstrap pairing port must close once mTLS is established (reducing the
// always-on pairing surface) and only re-open for initial pairing or an
// explicit renewal.
func TestShouldOpenBootstrap(t *testing.T) {
	tests := []struct {
		name       string
		phase      transport.Phase
		renewCerts bool
		want       bool
	}{
		{"initial pairing (no mTLS yet) opens bootstrap", transport.PhaseBootstrap, false, true},
		{"steady-state mTLS keeps bootstrap closed", transport.PhaseMTLS, false, false},
		{"mTLS + --renew-certs re-opens bootstrap", transport.PhaseMTLS, true, true},
		{"renew also opens during bootstrap phase", transport.PhaseBootstrap, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldOpenBootstrap(tt.phase, tt.renewCerts); got != tt.want {
				t.Errorf("shouldOpenBootstrap(%v, %v) = %v, want %v", tt.phase, tt.renewCerts, got, tt.want)
			}
		})
	}
}
