package cmd

import (
	"testing"

	"github.com/inovacc/sentinel/internal/settings"
)

func TestLimitsConfigDefaultsAreEnabled(t *testing.T) {
	// Guards the serve wiring contract: a default daemon config has limiting on
	// with the spec defaults, so serve.go threads real values into every layer.
	c := settings.DefaultConfig()
	if !c.Limits.Enabled {
		t.Fatal("default serve config must have limits enabled")
	}
	if c.Limits.MaxRecvMsgBytes != 1<<20 || c.Limits.RPCRatePerSec != 100 {
		t.Fatalf("unexpected limit defaults: %+v", c.Limits)
	}
}
