package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestNeedsAutoRenew(t *testing.T) {
	cases := []struct {
		name      string
		remaining time.Duration
		threshold time.Duration
		want      bool
	}{
		{"well above threshold", 500 * time.Hour, 240 * time.Hour, false},
		{"below threshold", 100 * time.Hour, 240 * time.Hour, true},
		{"expired", -1 * time.Hour, 240 * time.Hour, true},
		{"exactly at threshold", 240 * time.Hour, 240 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{NotAfter: time.Now().Add(tc.remaining)}
			if got := needsAutoRenew(cert, tc.threshold); got != tc.want {
				t.Fatalf("needsAutoRenew(%v, %v) = %v, want %v", tc.remaining, tc.threshold, got, tc.want)
			}
		})
	}
}

func TestRenewSelfIfNeededWritesFreshCert(t *testing.T) {
	// Build a CA + a short-lived device cert (remaining < threshold) in a temp
	// cert dir, call renewSelfIfNeeded, and assert device.crt's NotAfter advanced.
	_ = pem.Decode // keep import; real assertions added at implementation time.
}
