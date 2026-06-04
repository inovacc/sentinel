// Package audit records security-relevant events to a tamper-evident,
// actor-attributed store, separate from operational logs and session events.
//
// The Logger interface is injected the same way internal/confine.Confiner is:
// the real SQLite-backed implementation is wired once in cmd/serve.go, and a
// NopLogger zero value is used by every other caller and by tests, so wiring is
// purely additive and changes no existing behavior until the daemon injects the
// real logger.
package audit

import "context"

// Criticality is a static property of an event type (see catalog.go). It tells
// the caller what to do when Record fails: abort the operation (Critical) or
// log-and-continue (Routine).
type Criticality int

const (
	// Routine events log-and-continue on write failure.
	Routine Criticality = iota
	// Critical events abort the triggering operation on write failure.
	Critical
)

// Outcome is whether the audited action was allowed, denied, or errored.
type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeDeny  Outcome = "deny"
	OutcomeError Outcome = "error"
)

// Event is one security-relevant record. Actor identity is NOT a field here: it
// is extracted from the context inside Record (see WithActor) so a caller cannot
// forge the actor.
type Event struct {
	Type    string         // an Event* constant from catalog.go
	Outcome Outcome        // allow | deny | error
	Target  string         // resource/subject acted on (device id, path, cert subject)
	Detail  map[string]any // structured, JSON-serializable context; redacted before storage
}

// Logger records security-relevant events to a tamper-evident store.
type Logger interface {
	// Record appends one event. It returns an error if the event could not be
	// durably written. Callers decide what to do with that error based on the
	// event type's Criticality (see catalog.go and the tiered posture in §5 of
	// the design).
	Record(ctx context.Context, ev Event) error
	Close() error
}

// NopLogger is the zero-value Logger: it records nothing and never errors. It is
// the default for callers and tests so audit wiring is additive.
type NopLogger struct{}

func (NopLogger) Record(context.Context, Event) error { return nil }
func (NopLogger) Close() error                         { return nil }

// actor carries the authenticated identity of the request originator.
type actor struct {
	deviceID string
	role     string
}

type actorKey struct{}

// WithActor seeds the request context with the authenticated actor. It is called
// at the RBAC interceptor / transport boundary, where the peer certificate is
// available; Record reads it back so the actor cannot be supplied (and thus
// forged) by an ordinary caller.
func WithActor(ctx context.Context, deviceID, role string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor{deviceID: deviceID, role: role})
}

// actorFromContext returns the seeded actor, or the system actor ("", "system")
// when none was set (self/daemon-originated events).
func actorFromContext(ctx context.Context) actor {
	if a, ok := ctx.Value(actorKey{}).(actor); ok {
		return a
	}
	return actor{deviceID: "", role: "system"}
}

// _ ensures actorFromContext is referenced until store.go (Task 3) uses it.
var _ = actorFromContext
