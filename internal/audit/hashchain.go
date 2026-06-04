package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
)

// record is the fully-resolved row as it is stored and hashed. Field names and
// order here are load-bearing: canonicalPayload concatenates them in exactly
// this order, so changing the order is a breaking change to the chain format.
type record struct {
	Seq           int64
	TS            string // RFC3339Nano UTC
	ActorDeviceID string
	ActorRole     string
	EventType     string
	Criticality   Criticality
	Outcome       Outcome
	Target        string
	Detail        string // canonical JSON, "{}" if empty
	Segment       int64
	PrevHash      string
	Hash          string // filled in by computeHash; not part of the payload
}

// nul is the field separator. Using NUL (0x00) prevents any field value from
// being confused with a separator, since the textual fields cannot contain it
// (JSON encodes control chars, and the other fields are ids/timestamps/hashes).
const nul = "\x00"

// canonicalPayload builds the deterministic byte string that is hashed. Field
// order is fixed (matches §4.1 of the design): seq, ts, actor_device_id,
// actor_role, event_type, criticality, outcome, target, detail, prev_hash.
// Segment and Hash are intentionally excluded: segment is bookkeeping and hash
// is the output.
func canonicalPayload(r record) []byte {
	var b bytes.Buffer
	b.WriteString(strconv.FormatInt(r.Seq, 10))
	b.WriteString(nul)
	b.WriteString(r.TS)
	b.WriteString(nul)
	b.WriteString(r.ActorDeviceID)
	b.WriteString(nul)
	b.WriteString(r.ActorRole)
	b.WriteString(nul)
	b.WriteString(r.EventType)
	b.WriteString(nul)
	b.WriteString(strconv.Itoa(int(r.Criticality)))
	b.WriteString(nul)
	b.WriteString(string(r.Outcome))
	b.WriteString(nul)
	b.WriteString(r.Target)
	b.WriteString(nul)
	b.WriteString(r.Detail)
	b.WriteString(nul)
	b.WriteString(r.PrevHash)
	return b.Bytes()
}

// computeHash returns "sha256:" + hex(SHA-256(payload)).
func computeHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalDetailJSON renders a detail map as JSON with sorted keys, returning
// "{}" for nil/empty. Sorted keys make the stored detail (and thus the hash)
// deterministic across platforms and map-iteration order.
func canonicalDetailJSON(detail map[string]any) string {
	if len(detail) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(detail))
	for k := range detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(detail[k])
		if err != nil {
			vb = []byte(`null`)
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.String()
}
