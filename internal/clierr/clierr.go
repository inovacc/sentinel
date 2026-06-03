// Package clierr classifies low-level transport/TLS errors into actionable,
// human-readable CLI diagnostics. The mTLS handshake errors surfaced to users
// (e.g. "x509: certificate signed by unknown authority") are accurate but
// opaque; this package maps the known failure modes to a plain-language summary
// and a concrete remediation step.
package clierr

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// Kind classifies a recognized error into a remediation category.
type Kind int

const (
	// KindUnrecognized means the error did not match a known trust failure.
	KindUnrecognized Kind = iota
	// KindCATrust means the peer's cert could not be verified against the
	// trusted/pinned CA — typically a peer-side CA rotation.
	KindCATrust
	// KindCertExpired means a certificate in the chain has expired.
	KindCertExpired
)

// Diagnostic is a classified, user-facing explanation of a transport error.
type Diagnostic struct {
	Kind        Kind
	Summary     string
	Detail      string
	Remediation string
	Err         error
}

// Error renders the diagnostic as a multi-line message suitable for stderr.
func (d *Diagnostic) Error() string {
	var b strings.Builder
	b.WriteString(d.Summary)
	if d.Detail != "" {
		b.WriteString("\n  ")
		b.WriteString(d.Detail)
	}
	if d.Remediation != "" {
		b.WriteString("\n\n  → ")
		b.WriteString(d.Remediation)
	}
	return b.String()
}

// Unwrap exposes the underlying error for errors.Is/As.
func (d *Diagnostic) Unwrap() error { return d.Err }

const (
	caTrustRemediation = "The peer's certificate authority no longer matches the one pinned when you paired. " +
		"The peer most likely rotated its CA. Re-pair with the peer: `sentinel connect <host:7399> --force` " +
		"(and on the peer, run `sentinel renew` to reopen its bootstrap window)."
	certExpiredRemediation = "A certificate in the chain has expired. Renew it with `sentinel renew`, " +
		"then re-pair if the peer's CA also changed."
)

// Classify inspects err and, if it matches a known trust failure, returns a
// Diagnostic and true. It checks both typed x509 errors (direct verification
// failures) and message text (errors wrapped inside a gRPC status string, where
// the typed error is lost).
func Classify(err error) (*Diagnostic, bool) {
	if err == nil {
		return nil, false
	}

	// Expired is checked first: an expired cert can also read as a verify
	// failure, but the actionable fix differs.
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return &Diagnostic{
			Kind:        KindCertExpired,
			Summary:     "TLS certificate expired.",
			Detail:      err.Error(),
			Remediation: certExpiredRemediation,
			Err:         err,
		}, true
	}

	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return &Diagnostic{
			Kind:        KindCATrust,
			Summary:     "Peer certificate is not trusted (CA mismatch).",
			Detail:      err.Error(),
			Remediation: caTrustRemediation,
			Err:         err,
		}, true
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "certificate has expired"),
		strings.Contains(msg, "is not yet valid"):
		return &Diagnostic{
			Kind:        KindCertExpired,
			Summary:     "TLS certificate expired or not yet valid.",
			Detail:      err.Error(),
			Remediation: certExpiredRemediation,
			Err:         err,
		}, true
	case strings.Contains(msg, "certificate signed by unknown authority"),
		strings.Contains(msg, "peer cert not signed by ca"),
		strings.Contains(msg, "verification failure"),
		strings.Contains(msg, "tls: failed to verify certificate"),
		strings.Contains(msg, "authentication handshake failed"):
		return &Diagnostic{
			Kind:        KindCATrust,
			Summary:     "Peer certificate is not trusted (CA mismatch).",
			Detail:      err.Error(),
			Remediation: caTrustRemediation,
			Err:         err,
		}, true
	}

	return nil, false
}

// Explain returns a friendly, actionable message when err is a recognized trust
// failure, otherwise it returns the error's own message prefixed with "Error:".
func Explain(err error) string {
	if err == nil {
		return ""
	}
	if d, ok := Classify(err); ok {
		return d.Error()
	}
	return fmt.Sprintf("Error: %s", err.Error())
}
