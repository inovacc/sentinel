package cmd

import (
	"database/sql"
	"log/slog"
	"strings"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/fleet"

	_ "modernc.org/sqlite"
)

func newTestRegistry(t *testing.T) *fleet.Registry {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	reg, err := fleet.NewRegistry(db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

// TestBuildOnPeerAcceptedManualApproval verifies the reject-as-pending flow:
// a new peer is rejected and recorded pending; after approval it is signed.
func TestBuildOnPeerAcceptedManualApproval(t *testing.T) {
	reg := newTestRegistry(t)
	fn := buildOnPeerAccepted(slog.Default(), reg, audit.NopLogger{}, false /* autoAccept */)

	ok, err := fn("DEV-PEER-1", []byte("cert"), "operator")
	if ok || err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("new peer: (ok=%v, err=%v), want (false, pending error)", ok, err)
	}
	if reg.IsTrusted("DEV-PEER-1") {
		t.Fatal("peer must be pending (not trusted) before approval")
	}

	if err := reg.Accept("DEV-PEER-1", "operator"); err != nil {
		t.Fatalf("accept: %v", err)
	}

	ok, err = fn("DEV-PEER-1", []byte("cert"), "operator")
	if !ok || err != nil {
		t.Fatalf("after approval: (ok=%v, err=%v), want (true, nil)", ok, err)
	}
}

func TestBuildOnPeerAcceptedAutoAccept(t *testing.T) {
	reg := newTestRegistry(t)
	fn := buildOnPeerAccepted(slog.Default(), reg, audit.NopLogger{}, true /* autoAccept */)
	if ok, err := fn("DEV-X", []byte("c"), "operator"); !ok || err != nil {
		t.Fatalf("auto-accept: (ok=%v, err=%v), want (true, nil)", ok, err)
	}
}

// TestEnsureIdentityIdempotent: the package test datadir already has an identity
// (set up by TestMain), so ensureIdentity must not re-create it.
func TestEnsureIdentityIdempotent(t *testing.T) {
	created, err := ensureIdentity()
	if err != nil {
		t.Fatalf("ensureIdentity: %v", err)
	}
	if created {
		t.Error("expected created=false when CA and device cert already exist")
	}
}
