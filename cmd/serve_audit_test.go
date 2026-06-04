package cmd

import (
	"path/filepath"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/settings"
)

func TestBuildAuditLoggerEnabled(t *testing.T) {
	cfg := settings.DefaultConfig()
	cfg.Audit.DBPath = filepath.Join(t.TempDir(), "audit.db")
	l, err := buildAuditLogger(cfg, nil)
	if err != nil {
		t.Fatalf("buildAuditLogger: %v", err)
	}
	defer func() { _ = l.Close() }()
	if _, ok := l.(*audit.SQLiteLogger); !ok {
		t.Fatalf("enabled config should yield a SQLiteLogger, got %T", l)
	}
}

func TestBuildAuditLoggerDisabledIsNop(t *testing.T) {
	cfg := settings.DefaultConfig()
	cfg.Audit.Enabled = false
	l, err := buildAuditLogger(cfg, nil)
	if err != nil {
		t.Fatalf("buildAuditLogger: %v", err)
	}
	defer func() { _ = l.Close() }()
	if _, ok := l.(audit.NopLogger); !ok {
		t.Fatalf("disabled config should yield NopLogger, got %T", l)
	}
}
