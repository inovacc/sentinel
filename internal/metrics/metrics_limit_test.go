package metrics

import "testing"

func TestIncLimitExceeded(t *testing.T) {
	before := limitExceededTotal()
	IncLimitExceeded("bootstrap_ip")
	IncLimitExceeded("rpc_rate")
	if got := limitExceededTotal() - before; got != 2 {
		t.Fatalf("limitExceededTotal delta = %d, want 2", got)
	}
}
