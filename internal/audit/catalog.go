package audit

// Event type constants. Every constant here MUST appear in the catalog map
// below with a declared criticality; the registry-completeness test enforces it.
const (
	EventPairingAccept       = "pairing.accept"
	EventPairingReject       = "pairing.reject"
	EventPairingConflict     = "pairing.conflict"
	EventRBACDeny            = "rbac.deny"
	EventRBACAllowPrivileged = "rbac.allow.privileged"
	EventRBACAllowRead       = "rbac.allow.read"
	EventCertSign            = "cert.sign"
	EventCertRenew           = "cert.renew"
	EventCAPinChange         = "capin.change"
	EventSandboxDeny         = "sandbox.deny"
	EventConfineRefuse       = "confine.refuse"
	EventExecRun             = "exec.run"
	EventFleetAdd            = "fleet.add"
	EventFleetRemove         = "fleet.remove"
	EventDaemonStart         = "daemon.start"
	EventDaemonStop          = "daemon.stop"
	EventDaemonRenew         = "daemon.renew"
	EventFSRead              = "fs.read"
	EventAuditPrune          = "audit.prune"
)

// catalog maps every known event type to its static criticality. This is the
// single source of truth for the tiered fail-closed posture: criticality is a
// property of the event type, not a per-call decision, so a caller cannot
// downgrade a critical event.
var catalog = map[string]Criticality{
	EventPairingAccept:       Critical,
	EventPairingReject:       Critical,
	EventPairingConflict:     Critical,
	EventRBACDeny:            Critical,
	EventRBACAllowPrivileged: Critical,
	EventRBACAllowRead:       Routine,
	EventCertSign:            Critical,
	EventCertRenew:           Critical,
	EventCAPinChange:         Critical,
	EventSandboxDeny:         Critical,
	EventConfineRefuse:       Critical,
	EventExecRun:             Routine,
	EventFleetAdd:            Critical,
	EventFleetRemove:         Critical,
	EventDaemonStart:         Critical,
	EventDaemonStop:          Critical,
	EventDaemonRenew:         Critical,
	EventFSRead:              Routine,
	EventAuditPrune:          Routine,
}

// CriticalityOf returns the static criticality for an event type. ok is false
// for an unknown (unclassified) event type.
func CriticalityOf(eventType string) (Criticality, bool) {
	c, ok := catalog[eventType]
	return c, ok
}

// allEventTypes returns every classified event type, for the completeness test.
func allEventTypes() []string {
	out := make([]string, 0, len(catalog))
	for k := range catalog {
		out = append(out, k)
	}
	return out
}
