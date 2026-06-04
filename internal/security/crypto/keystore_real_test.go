//go:build keystore_smoke

package crypto

import (
	"bytes"
	"testing"
)

// TestRealKeyStorePersists exercises the actual OS keystore. It is build-tagged
// (keystore_smoke) and never runs in CI, which has no session keyring.
func TestRealKeyStorePersists(t *testing.T) {
	ks := NewOSKeyStore()
	if !ks.Available() {
		t.Skip("no OS keystore available on this host")
	}
	const acct = "smoke-test"
	want := []byte("0123456789abcdef0123456789abcdef")
	if err := ks.Set(keystoreService, acct, want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() { _ = ks.Delete(keystoreService, acct) })
	got, err := ks.Get(keystoreService, acct)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("keystore round-trip mismatch")
	}
}
