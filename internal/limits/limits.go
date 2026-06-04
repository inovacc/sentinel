// Package limits centralizes the Phase 3.2 breach contract: when any layer
// (bootstrap, mTLS listener, gRPC interceptor, process spawn) detects a
// resource-limit breach it rejects the request and calls Recorder.Record, which
// emits a single routine audit event and bumps the process-global metric. The
// audit event is routine on purpose: a write failure must never block a
// rejection (that would make the audit path itself a DoS vector).
package limits

import (
	"context"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/metrics"
)

// Kind labels the breach vector for the audit Detail and the metric.
const (
	KindBootstrapIP      = "bootstrap_ip"
	KindHandshakeTimeout = "handshake_timeout"
	KindConnCap          = "conn_cap"
	KindPerDeviceCap     = "per_device_cap"
	KindRPCRate          = "rpc_rate"
	KindMsgSize          = "msg_size"
	KindProcRlimit       = "proc_rlimit"
)

// Recorder turns a limit breach into a routine audit event + a metric bump. A
// nil *Recorder is a valid no-op so layers can be wired before the daemon's
// audit logger exists (and in tests).
type Recorder struct {
	logger audit.Logger
}

// NewRecorder builds a Recorder over the given audit logger. A nil logger is
// tolerated (the metric still increments, no event is written).
func NewRecorder(logger audit.Logger) *Recorder {
	return &Recorder{logger: logger}
}

// Record emits the breach contract: increment the metric, then write the routine
// limit.exceeded event. The audit-write error is swallowed (routine tier) so the
// caller's rejection always proceeds.
func (r *Recorder) Record(ctx context.Context, kind, source string) {
	metrics.IncLimitExceeded(kind)
	if r == nil || r.logger == nil {
		return
	}
	_ = r.logger.Record(ctx, audit.Event{
		Type:    audit.EventLimitExceeded,
		Outcome: audit.OutcomeDeny,
		Target:  source,
		Detail:  map[string]any{"kind": kind, "source": source},
	})
}
