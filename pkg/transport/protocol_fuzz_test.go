package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// envelopeBytes returns the wire representation of an envelope: 4-byte BE length
// followed by JSON-encoded Envelope. Used to seed the fuzz corpus with
// realistic inputs the parser must accept.
func envelopeBytes(t testing.TB, msgType MessageType, payload any) []byte {
	t.Helper()
	env, err := NewEnvelope(msgType, payload)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(data)))
	buf.Write(data)
	return buf.Bytes()
}

// FuzzDecodeEnvelope exercises the bootstrap protocol parser against arbitrary
// byte sequences. The parser must never panic, must never allocate beyond
// MaxEnvelopeSize, and must always either return a valid *Envelope or a non-nil error.
func FuzzDecodeEnvelope(f *testing.F) {
	// Seed with valid envelopes covering every message type.
	for _, mt := range []MessageType{
		MsgHello, MsgCertExchange, MsgCertRequest, MsgCertResponse,
		MsgAccept, MsgReject, MsgComplete, MsgError,
	} {
		f.Add(envelopeBytes(f, mt, map[string]any{"k": "v"}))
	}

	// Empty payload.
	f.Add(envelopeBytes(f, MsgHello, map[string]any{}))

	// Pathological seeds the parser must safely reject.
	// Length header claims max + 1 — must be rejected before allocation.
	tooBig := make([]byte, 4)
	binary.BigEndian.PutUint32(tooBig, MaxEnvelopeSize+1)
	f.Add(tooBig)

	// Length 0 — empty payload, json.Unmarshal on empty slice must fail cleanly.
	f.Add([]byte{0, 0, 0, 0})

	// Truncated header.
	f.Add([]byte{0, 0, 0})

	// Length larger than the actual data — EOF on payload read.
	f.Add([]byte{0, 0, 0, 0xff, 'a', 'b'})

	// Invalid JSON in payload.
	f.Add([]byte{0, 0, 0, 5, '{', '{', '{', '{', '{'})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Cap input at slightly above MaxEnvelopeSize to keep fuzz iterations bounded
		// — anything larger should be rejected by the length-prefix check anyway,
		// and is uninteresting to keep mutating.
		if len(data) > MaxEnvelopeSize+8 {
			t.Skip()
		}

		env, err := DecodeEnvelope(bytes.NewReader(data))

		// Invariant 1: never panics (handled by the test framework).
		// Invariant 2: exactly one of (env, err) is non-nil.
		if (env == nil) == (err == nil) {
			t.Fatalf("DecodeEnvelope returned (env=%v, err=%v); exactly one must be non-nil", env, err)
		}

		// Invariant 3: on success, DecodePayload must not panic on the returned envelope.
		if env != nil {
			var dst any
			_ = env.DecodePayload(&dst) // error is fine; panic is not
		}
	})
}

// TestDecodeEnvelopeKnownInputs validates DecodeEnvelope against hand-built
// inputs that exercise the parser's boundaries. Complements the fuzzer with
// deterministic regression cases.
func TestDecodeEnvelopeKnownInputs(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		wantErr bool
	}{
		{
			name:    "valid hello envelope",
			wire:    envelopeBytes(t, MsgHello, map[string]string{"device_id": "ABC"}),
			wantErr: false,
		},
		{
			name:    "length exceeds max",
			wire:    func() []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, MaxEnvelopeSize+1); return b }(),
			wantErr: true,
		},
		{
			name:    "truncated header (3 bytes)",
			wire:    []byte{0, 0, 0},
			wantErr: true,
		},
		{
			name:    "header ok, payload truncated",
			wire:    []byte{0, 0, 0, 10, '{', '"', 't', '"'},
			wantErr: true,
		},
		{
			name:    "invalid JSON in payload",
			wire: func() []byte {
				body := []byte("{not json")
				out := make([]byte, 4+len(body))
				binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
				copy(out[4:], body)
				return out
			}(),
			wantErr: true,
		},
		{
			name:    "empty payload (length 0)",
			wire:    []byte{0, 0, 0, 0},
			wantErr: true, // json.Unmarshal([]byte{}) → unexpected end of JSON input
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, err := DecodeEnvelope(bytes.NewReader(tc.wire))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got envelope=%v", env)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if env == nil {
				t.Fatal("want envelope, got nil")
			}
		})
	}
}
