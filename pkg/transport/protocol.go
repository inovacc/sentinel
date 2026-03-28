package transport

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// Bootstrap protocol messages exchanged over the Syncthing-key TLS connection.
// All messages are length-prefixed JSON.

// MessageType identifies the bootstrap protocol message.
type MessageType string

const (
	// MsgHello is the first message sent by both sides, containing device identity.
	MsgHello MessageType = "hello"
	// MsgCertExchange carries the CA certificate and a signed device certificate.
	MsgCertExchange MessageType = "cert_exchange"
	// MsgCertRequest asks the peer's CA to sign our CSR.
	MsgCertRequest MessageType = "cert_request"
	// MsgCertResponse returns the signed certificate.
	MsgCertResponse MessageType = "cert_response"
	// MsgAccept confirms the peer is accepted into the fleet.
	MsgAccept MessageType = "accept"
	// MsgReject indicates the peer was rejected.
	MsgReject MessageType = "reject"
	// MsgComplete signals bootstrap is done, transition to mTLS.
	MsgComplete MessageType = "complete"
	// MsgError carries an error description.
	MsgError MessageType = "error"
)

// Envelope wraps all bootstrap protocol messages.
type Envelope struct {
	Type      MessageType     `json:"type"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// NewEnvelope creates an envelope with the given type and payload.
func NewEnvelope(msgType MessageType, payload any) (*Envelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("transport: marshal payload: %w", err)
	}
	return &Envelope{
		Type:      msgType,
		Timestamp: time.Now().Unix(),
		Payload:   data,
	}, nil
}

// DecodePayload unmarshals the envelope payload into the target.
func (e *Envelope) DecodePayload(target any) error {
	return json.Unmarshal(e.Payload, target)
}

// --- Protocol Messages ---

// HelloMessage is exchanged first to identify each device.
type HelloMessage struct {
	// DeviceID is the Syncthing-style device ID (SHA-256 of cert → base32).
	DeviceID string `json:"device_id"`
	// Hostname of the device.
	Hostname string `json:"hostname"`
	// OS (runtime.GOOS).
	OS string `json:"os"`
	// Arch (runtime.GOARCH).
	Arch string `json:"arch"`
	// Version of sentinel.
	Version string `json:"version"`
	// HasCA indicates whether this device has a CA and can sign certificates.
	HasCA bool `json:"has_ca"`
	// HasMTLS indicates whether this device already has CA-signed certificates.
	HasMTLS bool `json:"has_mtls"`
	// RequestedRole is the role this device wants (only relevant for joining devices).
	RequestedRole string `json:"requested_role,omitempty"`
}

// CertExchangeMessage carries certificates for the mTLS transition.
type CertExchangeMessage struct {
	// CACertPEM is the CA certificate (PEM-encoded).
	CACertPEM string `json:"ca_cert_pem"`
	// DeviceCertPEM is the CA-signed device certificate (PEM-encoded).
	// Empty if the peer needs to request signing via CertRequest.
	DeviceCertPEM string `json:"device_cert_pem,omitempty"`
	// MTLSPort is the port to use for the mTLS connection after bootstrap.
	MTLSPort int `json:"mtls_port"`
}

// CertRequestMessage asks the CA to sign a CSR.
type CertRequestMessage struct {
	// CSRPEM is the certificate signing request (PEM-encoded).
	CSRPEM string `json:"csr_pem"`
	// RequestedRole for the signed certificate.
	RequestedRole string `json:"requested_role"`
}

// CertResponseMessage returns a signed certificate.
type CertResponseMessage struct {
	// SignedCertPEM is the CA-signed certificate (PEM-encoded).
	SignedCertPEM string `json:"signed_cert_pem"`
	// CACertPEM is the CA certificate for verification (PEM-encoded).
	CACertPEM string `json:"ca_cert_pem"`
	// AssignedRole may differ from requested (operator might grant reader).
	AssignedRole string `json:"assigned_role"`
}

// AcceptMessage confirms the peer into the fleet.
type AcceptMessage struct {
	// DeviceID of the accepted peer.
	DeviceID string `json:"device_id"`
	// AssignedRole for the peer.
	AssignedRole string `json:"assigned_role"`
}

// RejectMessage denies the peer.
type RejectMessage struct {
	// Reason for rejection.
	Reason string `json:"reason"`
}

// CompleteMessage signals bootstrap is done.
type CompleteMessage struct {
	// MTLSAddr is the address to reconnect to using mTLS.
	MTLSAddr string `json:"mtls_addr"`
	// DeviceID is the new device ID (from the CA-signed cert).
	DeviceID string `json:"device_id"`
}

// ErrorMessage carries an error.
type ErrorMessage struct {
	// Code is a machine-readable error code.
	Code string `json:"code"`
	// Message is a human-readable error description.
	Message string `json:"message"`
}

// decodeCertFromPEM parses a PEM-encoded certificate.
func decodeCertFromPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("transport: invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
