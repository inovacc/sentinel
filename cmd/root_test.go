package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Runtime errors must not dump the cobra usage block (the field evidence showed
// a full usage dump after an mTLS failure). Silencing both lets Execute print a
// single classified diagnostic instead.
func TestRootSilencesUsageAndErrors(t *testing.T) {
	if !rootCmd.SilenceUsage {
		t.Error("rootCmd.SilenceUsage should be true so runtime errors don't dump usage")
	}
	if !rootCmd.SilenceErrors {
		t.Error("rootCmd.SilenceErrors should be true so Execute prints the classified diagnostic")
	}
}

func TestReportError_FriendlyForTrustFailure(t *testing.T) {
	var buf bytes.Buffer
	err := errors.New(`rpc error: code = Unavailable desc = "transport: authentication handshake failed: client: peer cert not signed by CA: x509: certificate signed by unknown authority"`)
	reportError(&buf, err)
	out := strings.ToLower(buf.String())
	if !strings.Contains(out, "re-pair") {
		t.Errorf("expected a remediation hint, got: %s", buf.String())
	}
	if strings.Contains(out, "usage:") {
		t.Errorf("must not include usage block, got: %s", buf.String())
	}
}

func TestReportError_Nil(t *testing.T) {
	var buf bytes.Buffer
	reportError(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("nil error should produce no output, got: %s", buf.String())
	}
}
