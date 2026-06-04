package audit

import "testing"

func TestEveryCatalogEventHasCriticality(t *testing.T) {
	// allEventTypes is the exhaustive list of event-type constants. Every one
	// MUST be classified in the catalog, or adding an event without a tier
	// silently produces an un-audited (or mis-tiered) record.
	for _, et := range allEventTypes() {
		crit, ok := CriticalityOf(et)
		if !ok {
			t.Errorf("event type %q is not classified in the catalog", et)
			continue
		}
		if crit != Routine && crit != Critical {
			t.Errorf("event type %q has invalid criticality %d", et, crit)
		}
	}
}

func TestTierMatchesSpec(t *testing.T) {
	tests := []struct {
		eventType string
		want      Criticality
	}{
		{EventPairingAccept, Critical},
		{EventPairingReject, Critical},
		{EventPairingConflict, Critical},
		{EventRBACDeny, Critical},
		{EventRBACAllowPrivileged, Critical},
		{EventRBACAllowRead, Routine},
		{EventCertSign, Critical},
		{EventCertRenew, Critical},
		{EventCAPinChange, Critical},
		{EventSandboxDeny, Critical},
		{EventConfineRefuse, Critical},
		{EventExecRun, Routine},
		{EventFleetAdd, Critical},
		{EventFleetRemove, Critical},
		{EventDaemonStart, Critical},
		{EventDaemonStop, Critical},
		{EventDaemonRenew, Critical},
		{EventFSRead, Routine},
		{EventAuditPrune, Routine},
		{EventDeviceRevoked, Critical},
		{EventDeviceUnrevoked, Critical},
		{EventCAKeySealed, Critical},
		{EventCAKeyUnsealFail, Critical},
		{EventCertAutorenew, Routine},
	}
	for _, tt := range tests {
		got, ok := CriticalityOf(tt.eventType)
		if !ok {
			t.Errorf("%s: not in catalog", tt.eventType)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: tier = %d, want %d", tt.eventType, got, tt.want)
		}
	}
}

func TestUnknownEventTypeIsNotClassified(t *testing.T) {
	if _, ok := CriticalityOf("totally.unknown.event"); ok {
		t.Fatal("unknown event type unexpectedly classified")
	}
}
