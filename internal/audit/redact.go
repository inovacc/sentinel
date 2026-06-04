package audit

// allowedDetailKeys is the allowlist of Detail keys that may be stored. Any key
// not present is dropped, so a caller cannot accidentally persist arbitrary
// (possibly sensitive) context. Keep this list curated and minimal.
var allowedDetailKeys = map[string]struct{}{
	"command":     {},
	"argv":        {},
	"cwd":         {},
	"path":        {},
	"role":        {},
	"method":      {},
	"peer":        {},
	"device_id":   {},
	"subject":     {},
	"fingerprint": {},
	"reason":      {},
	"segment":     {},
	"binary":      {},
}

// sensitiveDetailKeys are keys that, if present, are replaced with a redaction
// marker rather than dropped — so the record shows the field existed but never
// stores its value.
var sensitiveDetailKeys = map[string]struct{}{
	"private_key": {},
	"key":         {},
	"password":    {},
	"secret":      {},
	"token":       {},
	"env":         {},
}

const redactedMarker = "[redacted]"

// redactDetail returns a copy of detail containing only allowlisted keys, with
// any sensitive key replaced by the redaction marker. nil in yields nil out.
func redactDetail(detail map[string]any) map[string]any {
	if len(detail) == 0 {
		return nil
	}
	out := make(map[string]any, len(detail))
	for k, v := range detail {
		if _, sensitive := sensitiveDetailKeys[k]; sensitive {
			out[k] = redactedMarker
			continue
		}
		if _, ok := allowedDetailKeys[k]; ok {
			out[k] = v
		}
		// else: silently dropped (not on the allowlist).
	}
	return out
}
