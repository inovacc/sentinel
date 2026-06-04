package crypto

import (
	"bytes"
	"testing"
)

func TestSealUnsealKeystoreMode(t *testing.T) {
	ks := NewFakeKeyStore()
	s, err := NewSealer(Options{Mode: ModeKeystore, KeyStore: ks})
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	key := []byte("ca-private-key-pem")
	sealed, err := s.Seal(key)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// A second Sealer reusing the same keystore must Unseal (DEK persisted).
	s2, err := NewSealer(Options{Mode: ModeKeystore, KeyStore: ks})
	if err != nil {
		t.Fatalf("NewSealer 2: %v", err)
	}
	got, err := s2.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("unseal mismatch")
	}
}

func TestSealPassphraseModeRoundTrip(t *testing.T) {
	var dekFile []byte
	opts := Options{
		Mode:       ModePassphraseEnv,
		Passphrase: []byte("hunter2"),
		LoadDEKFile: func() ([]byte, error) { return dekFile, nil },
		SaveDEKFile: func(b []byte) error { dekFile = b; return nil },
	}
	s, err := NewSealer(opts)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	sealed, err := s.Seal([]byte("k"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	s2, _ := NewSealer(opts) // reloads the wrapped DEK from dekFile
	if _, err := s2.Unseal(sealed); err != nil {
		t.Fatalf("Unseal after reload: %v", err)
	}
}

func TestSealerFailsClosedNoKeystoreNoPassphrase(t *testing.T) {
	ks := NewFakeKeyStore()
	ks.SetAvailable(false)
	_, err := NewSealer(Options{Mode: ModeKeystore, KeyStore: ks})
	if err == nil {
		t.Fatal("expected fail-closed error when keystore unavailable and no fallback")
	}
}

func TestSealerOffModeIsPassthrough(t *testing.T) {
	s, err := NewSealer(Options{Mode: ModeOff})
	if err != nil {
		t.Fatalf("NewSealer off: %v", err)
	}
	sealed, _ := s.Seal([]byte("plain"))
	if !bytes.Equal(sealed, []byte("plain")) {
		t.Fatal("off mode must pass plaintext through unchanged")
	}
}
