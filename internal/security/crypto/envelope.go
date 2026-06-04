package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// DEKSize is the Data Encryption Key length in bytes (AES-256).
const DEKSize = 32

// envelopeMagic and envelopeVersion frame the on-disk ciphertext so a plaintext
// PEM (which never starts with these bytes) is distinguishable from an envelope.
var envelopeMagic = []byte("SENTCAK1") // Sentinel CA Key, format 1

// NewDEK generates a fresh 32-byte random Data Encryption Key.
func NewDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("crypto: generate DEK: %w", err)
	}
	return dek, nil
}

// Encrypt seals plaintext with AES-256-GCM under dek. The output is
// magic || nonce || ciphertext(+tag). dek MUST be DEKSize bytes.
func Encrypt(dek, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	out := make([]byte, 0, len(envelopeMagic)+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, envelopeMagic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, envelopeMagic), nil
}

// Decrypt opens an envelope produced by Encrypt. It fails on any tamper (GCM
// auth) or framing error.
func Decrypt(dek, envelope []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if !IsEnvelope(envelope) {
		return nil, fmt.Errorf("crypto: not a sentinel key envelope")
	}
	body := envelope[len(envelopeMagic):]
	ns := gcm.NonceSize()
	if len(body) < ns {
		return nil, fmt.Errorf("crypto: envelope truncated")
	}
	nonce, ct := body[:ns], body[ns:]
	pt, err := gcm.Open(nil, nonce, ct, envelopeMagic)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt (auth failed — tampered or wrong key): %w", err)
	}
	return pt, nil
}

// IsEnvelope reports whether data begins with the envelope magic (i.e. is an
// encrypted key, not a plaintext PEM).
func IsEnvelope(data []byte) bool {
	if len(data) < len(envelopeMagic) {
		return false
	}
	for i := range envelopeMagic {
		if data[i] != envelopeMagic[i] {
			return false
		}
	}
	return true
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("crypto: DEK must be %d bytes, got %d", DEKSize, len(dek))
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return gcm, nil
}
