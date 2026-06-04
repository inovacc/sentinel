package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
)

func seedAuditDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := audit.Open(audit.Options{DBPath: path, SegmentMax: 100})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := audit.WithActor(context.Background(), "DEV1", "admin")
	for _, et := range []string{audit.EventCertSign, audit.EventExecRun, audit.EventRBACDeny} {
		if err := l.Record(ctx, audit.Event{Type: et, Outcome: audit.OutcomeAllow, Target: "t"}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	_ = l.Close()
	return path
}

func TestAuditTailCmd(t *testing.T) {
	path := seedAuditDB(t)
	var out bytes.Buffer
	if err := runAuditTail(&out, path, auditFilterFlags{n: 2}); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if !strings.Contains(out.String(), "exec.run") {
		t.Fatalf("tail output missing exec.run: %q", out.String())
	}
}

func TestAuditVerifyCmdClean(t *testing.T) {
	path := seedAuditDB(t)
	var out bytes.Buffer
	if err := runAuditVerify(&out, path, 0); err != nil {
		t.Fatalf("verify clean should succeed: %v", err)
	}
}

func TestAuditVerifyCmdDetectsTamper(t *testing.T) {
	path := seedAuditDB(t)
	// Reopen and tamper.
	l, err := audit.Open(audit.Options{DBPath: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := l.TamperForTest(); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	_ = l.Close()

	var out bytes.Buffer
	if err := runAuditVerify(&out, path, 0); err == nil {
		t.Fatal("verify should fail on a tampered chain")
	}
}

func TestAuditExportCmdJSON(t *testing.T) {
	path := seedAuditDB(t)
	var out bytes.Buffer
	if err := runAuditExport(&out, path, "json", auditFilterFlags{}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(out.String(), "cert.sign") {
		t.Fatalf("export missing cert.sign: %q", out.String())
	}
}
