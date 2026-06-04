package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. These are conservative interactive defaults; the salt is
// stored alongside the wrapped DEK so they need not be configurable for v1.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonSalt    = 16
)

var wrapMagic = []byte("SENTDEK1") // Sentinel wrapped-DEK, format 1

// WrapDEK derives a 32-byte key from passphrase via argon2id and uses it to
// AES-256-GCM-encrypt dek. Output: wrapMagic || salt || envelope(wrapKey, dek).
func WrapDEK(passphrase, dek []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("crypto: empty passphrase")
	}
	salt := make([]byte, argonSalt)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("crypto: salt: %w", err)
	}
	wrapKey := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, DEKSize)
	sealed, err := Encrypt(wrapKey, dek)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(wrapMagic)+len(salt)+len(sealed))
	out = append(out, wrapMagic...)
	out = append(out, salt...)
	return append(out, sealed...), nil
}

// UnwrapDEK reverses WrapDEK. Wrong passphrase fails the GCM auth tag.
func UnwrapDEK(passphrase, wrapped []byte) ([]byte, error) {
	if len(wrapped) < len(wrapMagic)+argonSalt {
		return nil, fmt.Errorf("crypto: wrapped DEK truncated")
	}
	for i := range wrapMagic {
		if wrapped[i] != wrapMagic[i] {
			return nil, fmt.Errorf("crypto: not a wrapped DEK blob")
		}
	}
	rest := wrapped[len(wrapMagic):]
	salt, sealed := rest[:argonSalt], rest[argonSalt:]
	wrapKey := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, DEKSize)
	dek, err := Decrypt(wrapKey, sealed)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap DEK (wrong passphrase?): %w", err)
	}
	return dek, nil
}
