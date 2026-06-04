package audit

import (
	"strings"
	"testing"
)

func TestComputeHashFormatAndDeterminism(t *testing.T) {
	rec := record{
		Seq:           1,
		TS:            "2026-06-04T10:00:00Z",
		ActorDeviceID: "DEV1",
		ActorRole:     "admin",
		EventType:     EventCertSign,
		Criticality:   Critical,
		Outcome:       OutcomeAllow,
		Target:        "CN=device,O=sentinel",
		Detail:        `{"role":"operator"}`,
		PrevHash:      "",
	}
	h1 := computeHash(canonicalPayload(rec))
	h2 := computeHash(canonicalPayload(rec))
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("hash missing sha256: prefix: %q", h1)
	}
	if len(h1) != len("sha256:")+64 {
		t.Fatalf("hash wrong length: %q (len %d)", h1, len(h1))
	}
}

func TestCanonicalDetailHasSortedKeys(t *testing.T) {
	// Two semantically equal detail strings with different key order must
	// canonicalize to the same payload (the store always passes sorted-key JSON,
	// but the canonicalizer must not depend on insertion order of the source).
	a := canonicalDetailJSON(map[string]any{"b": 2, "a": 1})
	b := canonicalDetailJSON(map[string]any{"a": 1, "b": 2})
	if a != b {
		t.Fatalf("canonical detail not order-independent: %q vs %q", a, b)
	}
	if a != `{"a":1,"b":2}` {
		t.Fatalf("canonical detail = %q, want sorted-key JSON", a)
	}
}

func TestEmptyDetailIsEmptyObject(t *testing.T) {
	if got := canonicalDetailJSON(nil); got != "{}" {
		t.Fatalf("nil detail = %q, want {}", got)
	}
	if got := canonicalDetailJSON(map[string]any{}); got != "{}" {
		t.Fatalf("empty detail = %q, want {}", got)
	}
}

func TestAnyFieldChangeChangesHash(t *testing.T) {
	base := record{Seq: 1, TS: "t", ActorDeviceID: "d", ActorRole: "r",
		EventType: "e", Criticality: Routine, Outcome: OutcomeAllow,
		Target: "g", Detail: "{}", PrevHash: ""}
	baseHash := computeHash(canonicalPayload(base))

	mutated := base
	mutated.Target = "g2"
	if computeHash(canonicalPayload(mutated)) == baseHash {
		t.Fatal("changing Target did not change the hash")
	}
}
