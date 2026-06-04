package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dek := mustDEK(t)
	plaintext := []byte("-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----\n")

	ct, err := Encrypt(dek, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := Decrypt(dek, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	dek := mustDEK(t)
	ct, err := Encrypt(dek, []byte("secret-key-material"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[len(ct)-1] ^= 0xFF // flip a ciphertext byte
	if _, err := Decrypt(dek, ct); err == nil {
		t.Fatal("expected auth failure on tampered ciphertext, got nil")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	ct, err := Encrypt(mustDEK(t), []byte("secret-key-material"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(mustDEK(t), ct); err == nil {
		t.Fatal("expected failure decrypting with a different DEK")
	}
}

func TestEncryptRejectsBadDEKLength(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), []byte("x")); err == nil {
		t.Fatal("expected error for 16-byte DEK (must be 32)")
	}
}

func mustDEK(t *testing.T) []byte {
	t.Helper()
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	if len(dek) != DEKSize {
		t.Fatalf("DEK size = %d, want %d", len(dek), DEKSize)
	}
	return dek
}
