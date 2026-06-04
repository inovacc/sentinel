package crypto

import (
	"bytes"
	"testing"
)

func TestWrapUnwrapDEKRoundTrip(t *testing.T) {
	dek := mustDEK(t)
	wrapped, err := WrapDEK([]byte("correct horse battery staple"), dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped blob leaks the DEK")
	}
	got, err := UnwrapDEK([]byte("correct horse battery staple"), wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK mismatch")
	}
}

func TestUnwrapWrongPassphraseFails(t *testing.T) {
	wrapped, err := WrapDEK([]byte("right"), mustDEK(t))
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if _, err := UnwrapDEK([]byte("wrong"), wrapped); err == nil {
		t.Fatal("expected failure unwrapping with wrong passphrase")
	}
}

func TestWrapRejectsEmptyPassphrase(t *testing.T) {
	if _, err := WrapDEK(nil, mustDEK(t)); err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}
