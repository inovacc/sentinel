package audit

import (
	"context"
	"testing"
)

// TestNopLoggerSatisfiesInterface guards that NopLogger remains a usable Logger
// (the zero value relied on by existing callers and tests).
func TestNopLoggerSatisfiesInterface(t *testing.T) {
	var l Logger = NopLogger{}
	if err := l.Record(context.Background(), Event{Type: EventExecRun, Outcome: OutcomeAllow}); err != nil {
		t.Fatalf("NopLogger.Record returned error: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("NopLogger.Close returned error: %v", err)
	}
}

// TestSQLiteLoggerSatisfiesInterface guards the real implementation conforms.
func TestSQLiteLoggerSatisfiesInterface(t *testing.T) {
	var _ Logger = (*SQLiteLogger)(nil)
}
