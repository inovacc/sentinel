package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMetricsEndpointReportsLimitExceeded(t *testing.T) {
	before := limitExceededTotal()
	IncLimitExceeded("conn_cap")

	h := NewHandler(time.Now(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	var body struct {
		LimitExceededTotal uint64 `json:"limit_exceeded_total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.LimitExceededTotal <= before {
		t.Fatalf("limit_exceeded_total = %d, want > %d", body.LimitExceededTotal, before)
	}
}
