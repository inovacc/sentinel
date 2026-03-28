package ca

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"strings"
)

// DeviceID computes a Syncthing-style device ID from a certificate PEM.
// The ID is the SHA-256 hash of the DER bytes, encoded as base32 (no padding),
// with Luhn check characters inserted, formatted with dashes every 7 chars.
func DeviceID(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("ca: invalid certificate PEM for device ID")
	}

	hash := sha256.Sum256(block.Bytes)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])

	// Split into groups of 13 (7 data + 6 data), then insert Luhn check chars.
	// The base32 of SHA-256 (32 bytes) = 52 chars.
	// We split into groups of 7, compute Luhn for each group, append check char.
	// This gives us groups of 7+1=8 chars, separated by dashes.

	var groups []string
	for i := 0; i < len(encoded); i += 7 {
		end := i + 7
		if end > len(encoded) {
			end = len(encoded)
		}
		group := encoded[i:end]
		check := luhnCheckChar(group)
		groups = append(groups, group+string(check))
	}

	return strings.Join(groups, "-"), nil
}

// ValidateDeviceID validates a device ID string by checking Luhn digits.
func ValidateDeviceID(id string) bool {
	groups := strings.Split(id, "-")
	if len(groups) == 0 {
		return false
	}

	for _, g := range groups {
		if len(g) < 2 {
			return false
		}
		data := g[:len(g)-1]
		check := g[len(g)-1]
		if luhnCheckChar(data) != check {
			return false
		}
	}
	return true
}

// luhnCheckChar computes a Luhn check character for a base32 group.
// Uses the Luhn mod N algorithm with the base32 alphabet (A-Z, 2-7).
func luhnCheckChar(group string) byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	n := len(alphabet)

	factor := 1
	sum := 0

	for i := len(group) - 1; i >= 0; i-- {
		codePoint := strings.IndexByte(alphabet, group[i])
		if codePoint < 0 {
			return '0'
		}
		addend := factor * codePoint
		factor = 3 - factor // alternate between 1 and 2
		addend = (addend / n) + (addend % n)
		sum += addend
	}

	remainder := sum % n
	checkCodePoint := (n - remainder) % n
	return alphabet[checkCodePoint]
}
