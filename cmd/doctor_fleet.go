package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/sentinel/internal/clierr"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/fleet"
)

// errInvalidPinnedCA marks a peer whose stored pinned CA certificate is itself
// unparseable (e.g. registry corruption) — a hard trust failure, not a mere
// reachability warning.
var errInvalidPinnedCA = errors.New("invalid pinned CA certificate")

// peerProbe is the trust-verification outcome for a single fleet peer.
type peerProbe struct {
	deviceID string
	status   docStatus
	detail   string
}

const fleetTrustCheck = "fleet peer trust"

// checkFleetTrust dials every trusted peer that has a pinned CA and verifies the
// peer still serves a certificate signed by that pinned CA. This is the check
// that would have caught the field failure where a peer rotated its CA: the
// local-only checks all reported green while the data plane was unusable.
func checkFleetTrust() docResult {
	reg, cleanup, err := openRegistry()
	if err != nil {
		// A missing/locked registry is not a fleet-trust problem; the data-dir
		// and config checks cover store health. Skip rather than alarm.
		return docResult{fleetTrustCheck, stOK, "registry unavailable — skipped"}
	}
	defer cleanup()

	// Present our own device identity so a peer that requires client auth lets us
	// complete the handshake. This is best-effort: a missing device cert is a
	// FAIL in its own check (checkDeviceCert), and without it a mutual-auth peer
	// surfaces here as a WARN ("unreachable") rather than a false OK.
	certDir, _ := datadir.CertDir()
	clientCertPEM, _ := os.ReadFile(filepath.Join(certDir, "device.crt"))
	clientKeyPEM, _ := os.ReadFile(filepath.Join(certDir, "device.key"))

	var probes []peerProbe
	for _, status := range []fleet.DeviceStatus{fleet.StatusOnline, fleet.StatusOffline} {
		devices, err := reg.List(status)
		if err != nil {
			return docResult{fleetTrustCheck, stWarn, fmt.Sprintf("list peers: %v", err)}
		}
		for _, d := range devices {
			if d.Address == "" || len(d.CACertPEM) == 0 {
				continue // nothing to verify against (legacy/unpinned peer)
			}
			derr := dialPeerTrust(d.Address, d.CACertPEM, clientCertPEM, clientKeyPEM, 4*time.Second)
			probes = append(probes, classifyPeerProbe(d.DeviceID, derr))
		}
	}
	return summarizeFleetTrust(probes)
}

// dialPeerTrust performs a TLS handshake to addr and verifies the peer's
// certificate chains to the pinned CA. It mirrors the client's verification
// (manual chain check, no SAN requirement) so only a genuine trust failure —
// not a hostname mismatch — is reported. A nil return means the peer is trusted.
func dialPeerTrust(addr string, pinnedCAPEM, clientCertPEM, clientKeyPEM []byte, timeout time.Duration) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pinnedCAPEM) {
		return fmt.Errorf("%w for %s", errInvalidPinnedCA, addr)
	}

	var certs []tls.Certificate
	if len(clientCertPEM) > 0 && len(clientKeyPEM) > 0 {
		if c, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM); err == nil {
			certs = append(certs, c)
		}
	}

	cfg := &tls.Config{
		Certificates:       certs,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // manual verify below (no SAN), matching the client
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer presented no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse peer certificate: %w", err)
			}
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool})
			return err
		},
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}

// classifyPeerProbe maps a dial outcome to a doctor status. A reachable peer
// whose cert is untrusted (CA rotation) or expired is a hard failure; an
// unreachable peer is only a warning since trust cannot be concluded.
func classifyPeerProbe(deviceID string, dialErr error) peerProbe {
	if dialErr == nil {
		return peerProbe{deviceID, stOK, "verified against pinned CA"}
	}
	if errors.Is(dialErr, errInvalidPinnedCA) {
		return peerProbe{deviceID, stFail, "pinned CA certificate is unreadable (registry corruption?) — re-pair"}
	}
	if d, ok := clierr.Classify(dialErr); ok {
		switch d.Kind {
		case clierr.KindCATrust:
			return peerProbe{deviceID, stFail, "serves a cert not signed by its pinned CA — re-pair (sentinel connect <host:7399> --force)"}
		case clierr.KindCertExpired:
			return peerProbe{deviceID, stFail, "certificate expired — renew"}
		}
	}
	return peerProbe{deviceID, stWarn, "unreachable (" + firstLine(dialErr.Error()) + ")"}
}

// summarizeFleetTrust folds per-peer probes into a single doctor result, worst
// status winning, with the offending peers named.
func summarizeFleetTrust(probes []peerProbe) docResult {
	if len(probes) == 0 {
		return docResult{fleetTrustCheck, stOK, "no pinned peers to verify"}
	}
	var okN, warnN, failN int
	var notes []string
	for _, p := range probes {
		switch p.status {
		case stOK:
			okN++
		case stWarn:
			warnN++
			notes = append(notes, shortDeviceID(p.deviceID)+": "+p.detail)
		case stFail:
			failN++
			notes = append(notes, shortDeviceID(p.deviceID)+": "+p.detail)
		case stFixed:
			okN++
		}
	}
	switch {
	case failN > 0:
		return docResult{fleetTrustCheck, stFail, fmt.Sprintf("%d of %d peer(s) untrusted — %s", failN, len(probes), strings.Join(notes, "; "))}
	case warnN > 0:
		return docResult{fleetTrustCheck, stWarn, fmt.Sprintf("%d of %d peer(s) unreachable — %s", warnN, len(probes), strings.Join(notes, "; "))}
	default:
		return docResult{fleetTrustCheck, stOK, fmt.Sprintf("%d peer(s) verified against pinned CA", okN)}
	}
}

// shortDeviceID trims a long device ID to its first group for readable output.
func shortDeviceID(id string) string {
	if i := strings.IndexByte(id, '-'); i > 0 {
		return id[:i] + "-…"
	}
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

// firstLine returns the first line of s, keeping multi-line dial errors compact.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
