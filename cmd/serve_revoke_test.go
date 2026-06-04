package cmd

import (
	"context"
	"database/sql"
	"testing"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/fleet"
	sentinelgrpc "github.com/inovacc/sentinel/internal/grpc"
	"github.com/inovacc/sentinel/internal/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "modernc.org/sqlite"
)

// TestHeartbeatRejectsRevokedDevice verifies the in-band revocation sweep:
// when a device is revoked in the fleet registry, the next Heartbeat call for
// a session owned by that device returns codes.PermissionDenied.
//
// Implementation note: we use the session DeviceID field (client-supplied) as
// the owner identifier rather than the sha256: actor from the gRPC TLS peer
// context. The sha256 fingerprint used by the RBAC interceptor is a different
// format from the Syncthing-style ID stored in the fleet registry. The v1
// in-band check reads sess.DeviceID and checks registry.IsRevoked — this is
// the minimal approach that avoids threading the Syncthing ID through the mTLS
// peer context. A future hardening pass can switch to the cert-derived ID.
func TestHeartbeatRejectsRevokedDevice(t *testing.T) {
	db, err := sql.Open("sqlite", "file:heartbeat_revoke_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	registry, err := fleet.NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	sessionMgr, err := session.NewManager(db)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	const devID = "DEV-REVOKE-TEST-1"

	// Add the device to the fleet registry so Revoke() can find it.
	if err := registry.AddPending(&fleet.Device{DeviceID: devID, Role: "reader"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	// Create an active session owned by devID.
	ctx := context.Background()
	sess, err := sessionMgr.Create(ctx, devID, "proj", "desc", "/tmp", nil)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	svc := sentinelgrpc.NewSessionService(sessionMgr).WithRevocationChecker(registry.IsRevoked)

	// Before revocation: heartbeat should succeed.
	if _, err := svc.Heartbeat(ctx, &v1.HeartbeatRequest{SessionId: sess.ID}); err != nil {
		t.Fatalf("Heartbeat before revocation: %v", err)
	}

	// Revoke the device.
	if err := registry.Revoke(devID, "test revocation"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// After revocation: heartbeat must return PermissionDenied.
	_, err = svc.Heartbeat(ctx, &v1.HeartbeatRequest{SessionId: sess.ID})
	if err == nil {
		t.Fatal("expected PermissionDenied after revocation, got nil")
	}
	if code := status.Code(err); code != codes.PermissionDenied {
		t.Fatalf("expected codes.PermissionDenied, got %v", code)
	}
}
