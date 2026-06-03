package clierr

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The exact gRPC-wrapped error string observed in the field (F:\evicende_sentinel
// 06-exec-error.txt). The typed x509 error is lost inside the gRPC status string,
// so classification must also work on message text.
const fieldHandshakeErr = `exec: client: exec: rpc error: code = Unavailable desc = connection error: desc = "transport: authentication handshake failed: client: peer cert not signed by CA: x509: certificate signed by unknown authority (possibly because of \"x509: ECDSA verification failure\" while trying to verify candidate authority certificate \"Sentinel Root CA\")"`

func TestClassify_FieldHandshakeError(t *testing.T) {
	d, ok := Classify(errors.New(fieldHandshakeErr))
	if !ok {
		t.Fatal("expected field handshake error to be recognized")
	}
	if d.Kind != KindCATrust {
		t.Fatalf("Kind = %v, want KindCATrust", d.Kind)
	}
	if !strings.Contains(strings.ToLower(d.Remediation), "re-pair") {
		t.Errorf("remediation should mention re-pair, got %q", d.Remediation)
	}
}

func TestClassify_TypedUnknownAuthority(t *testing.T) {
	err := fmt.Errorf("dial peer: %w", x509.UnknownAuthorityError{})
	d, ok := Classify(err)
	if !ok || d.Kind != KindCATrust {
		t.Fatalf("typed UnknownAuthorityError not classified as CA trust (ok=%v)", ok)
	}
}

func TestClassify_ExpiredCert(t *testing.T) {
	err := errors.New("x509: certificate has expired or is not yet valid: current time after 2027")
	d, ok := Classify(err)
	if !ok {
		t.Fatal("expected expired cert to be recognized")
	}
	if d.Kind != KindCertExpired {
		t.Fatalf("Kind = %v, want KindCertExpired", d.Kind)
	}
	if !strings.Contains(strings.ToLower(d.Remediation), "renew") {
		t.Errorf("remediation should mention renew, got %q", d.Remediation)
	}
}

func TestClassify_TypedExpired(t *testing.T) {
	err := fmt.Errorf("verify: %w", x509.CertificateInvalidError{Reason: x509.Expired})
	d, ok := Classify(err)
	if !ok || d.Kind != KindCertExpired {
		t.Fatalf("typed expired cert not classified (ok=%v)", ok)
	}
}

func TestClassify_Unrecognized(t *testing.T) {
	if _, ok := Classify(errors.New("connection refused")); ok {
		t.Error("connection refused should not be a recognized trust diagnostic")
	}
}

func TestClassify_Nil(t *testing.T) {
	if _, ok := Classify(nil); ok {
		t.Error("nil error should not be recognized")
	}
}

func TestExplain_RecognizedIncludesRemediation(t *testing.T) {
	s := Explain(errors.New(fieldHandshakeErr))
	if !strings.Contains(strings.ToLower(s), "re-pair") {
		t.Errorf("Explain should surface remediation, got: %s", s)
	}
}

func TestExplain_UnrecognizedFallsBack(t *testing.T) {
	s := Explain(errors.New("boom widget exploded"))
	if !strings.Contains(s, "boom widget exploded") {
		t.Errorf("Explain should fall back to original message, got: %s", s)
	}
}

func TestDiagnostic_ErrorAndUnwrap(t *testing.T) {
	base := errors.New(fieldHandshakeErr)
	d, _ := Classify(base)
	if !errors.Is(d, base) {
		t.Error("Diagnostic should unwrap to the original error")
	}
	if !strings.Contains(d.Error(), d.Remediation) {
		t.Error("Diagnostic.Error() should include the remediation")
	}
}
