// Package fleet manages the device fleet registry with SQLite persistence.
package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/inovacc/sentinel/internal/audit"
)

// DeviceStatus represents the connection state of a device.
type DeviceStatus string

const (
	StatusOnline  DeviceStatus = "online"
	StatusOffline DeviceStatus = "offline"
	StatusPending DeviceStatus = "pending"
)

// Device represents a registered device in the fleet.
type Device struct {
	DeviceID   string            `json:"device_id"`
	Hostname   string            `json:"hostname"`
	OS         string            `json:"os"`
	Arch       string            `json:"arch"`
	Role       string            `json:"role"`
	Status     DeviceStatus      `json:"status"`
	Address    string            `json:"address"`
	CertPEM    []byte            `json:"-"`
	LastSeenAt time.Time         `json:"last_seen_at"`
	CreatedAt  time.Time         `json:"created_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`

	// CAFingerprint is the "sha256:<hex>" fingerprint of the CA certificate
	// this peer was paired with. It pins the trust anchor so a later CA
	// rotation by the peer is detectable rather than a silent handshake break.
	CAFingerprint string `json:"ca_fingerprint,omitempty"`
	// CACertPEM is the PEM of the CA certificate pinned at pairing time. It is
	// the trust root used to verify this specific peer's mTLS chain.
	CACertPEM []byte `json:"-"`

	// Revoked marks a device whose certificate is no longer accepted at the mTLS
	// handshake (T8.4 local revocation). RevokedAt/RevokedReason are set by Revoke.
	Revoked       bool      `json:"revoked"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	RevokedReason string    `json:"revoked_reason,omitempty"`
}

// Option configures a Registry.
type Option func(*Registry)

// WithAuditLogger sets the security audit logger. It mirrors the worker.Pool
// pattern: the logger is never nil (NopLogger by default), so emission sites are
// unconditional and a missing logger silently records nothing.
func WithAuditLogger(l audit.Logger) Option {
	return func(r *Registry) {
		if l != nil {
			r.auditLog = l
		}
	}
}

// Registry manages the fleet of known devices.
type Registry struct {
	db       *sql.DB
	auditLog audit.Logger
}

// NewRegistry creates a fleet registry with SQLite persistence.
func NewRegistry(db *sql.DB, opts ...Option) (*Registry, error) {
	r := &Registry{db: db, auditLog: audit.NopLogger{}}
	for _, o := range opts {
		o(r)
	}
	if r.auditLog == nil {
		r.auditLog = audit.NopLogger{}
	}
	if err := r.migrate(); err != nil {
		return nil, fmt.Errorf("fleet: migrate schema: %w", err)
	}
	return r, nil
}

// SetAuditLogger swaps the audit logger after construction. The daemon builds
// the Registry before the audit logger exists (see cmd/serve.go ordering), so a
// setter is provided in addition to the functional option. A nil logger is
// ignored to preserve the never-nil invariant.
func (r *Registry) SetAuditLogger(l audit.Logger) {
	if l != nil {
		r.auditLog = l
	}
}

func (r *Registry) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS fleet_devices (
    device_id      TEXT PRIMARY KEY,
    hostname       TEXT NOT NULL DEFAULT '',
    os             TEXT NOT NULL DEFAULT '',
    arch           TEXT NOT NULL DEFAULT '',
    role           TEXT NOT NULL DEFAULT 'reader',
    status         TEXT NOT NULL DEFAULT 'pending',
    address        TEXT NOT NULL DEFAULT '',
    cert_pem       BLOB,
    last_seen_at   INTEGER NOT NULL,
    created_at     INTEGER NOT NULL,
    metadata       TEXT DEFAULT '{}',
    ca_fingerprint TEXT NOT NULL DEFAULT '',
    ca_cert_pem    BLOB,
    revoked        INTEGER NOT NULL DEFAULT 0,
    revoked_at     TEXT,
    reason         TEXT
);
CREATE INDEX IF NOT EXISTS idx_fleet_status ON fleet_devices(status);
`
	if _, err := r.db.Exec(schema); err != nil {
		return err
	}
	// Additive migration for databases created before the CA-pin columns
	// existed. New columns are added in place; existing rows keep their data.
	for _, c := range []struct{ name, ddl string }{
		{"ca_fingerprint", "ALTER TABLE fleet_devices ADD COLUMN ca_fingerprint TEXT NOT NULL DEFAULT ''"},
		{"ca_cert_pem", "ALTER TABLE fleet_devices ADD COLUMN ca_cert_pem BLOB"},
		{"revoked", "ALTER TABLE fleet_devices ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0"},
		{"revoked_at", "ALTER TABLE fleet_devices ADD COLUMN revoked_at TEXT"},
		{"reason", "ALTER TABLE fleet_devices ADD COLUMN reason TEXT"},
	} {
		has, err := r.hasColumn("fleet_devices", c.name)
		if err != nil {
			return fmt.Errorf("fleet: inspect column %s: %w", c.name, err)
		}
		if has {
			continue
		}
		if _, err := r.db.Exec(c.ddl); err != nil {
			return fmt.Errorf("fleet: add column %s: %w", c.name, err)
		}
	}
	return nil
}

// hasColumn reports whether the named column exists on the given table.
func (r *Registry) hasColumn(table, column string) (bool, error) {
	rows, err := r.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid         int
			name, ctype string
			notNull, pk int
			dfltValue   sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// AddPending adds a device as pending (awaiting approval).
func (r *Registry) AddPending(d *Device) error {
	meta, _ := json.Marshal(d.Metadata)
	now := time.Now().Unix()
	_, err := r.db.Exec(
		`INSERT OR REPLACE INTO fleet_devices (device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata, ca_fingerprint, ca_cert_pem)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceID, d.Hostname, d.OS, d.Arch, d.Role, string(StatusPending), d.Address, d.CertPEM, now, now, string(meta), d.CAFingerprint, d.CACertPEM,
	)
	if err != nil {
		return fmt.Errorf("fleet: add pending device: %w", err)
	}
	return nil
}

// Accept changes a pending device to online with the given role.
func (r *Registry) Accept(deviceID, role string) error {
	res, err := r.db.Exec(
		`UPDATE fleet_devices SET status = ?, role = ?, last_seen_at = ? WHERE device_id = ?`,
		string(StatusOnline), role, time.Now().Unix(), deviceID,
	)
	if err != nil {
		return fmt.Errorf("fleet: accept device: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("fleet: device %s not found", deviceID)
	}
	return nil
}

// Reject removes a pending device from the registry.
func (r *Registry) Reject(deviceID string) error {
	res, err := r.db.Exec(
		`DELETE FROM fleet_devices WHERE device_id = ? AND status = ?`,
		deviceID, string(StatusPending),
	)
	if err != nil {
		return fmt.Errorf("fleet: reject device: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("fleet: device %s not found or not pending", deviceID)
	}
	return nil
}

// Remove removes any device from the registry. Removal is a critical fleet
// mutation: when a row is actually deleted it emits fleet.remove and fails
// closed if that audit write fails (the catalog classifies fleet.remove as
// Critical), so a removal can never go unrecorded.
func (r *Registry) Remove(deviceID string) error {
	res, err := r.db.Exec(`DELETE FROM fleet_devices WHERE device_id = ?`, deviceID)
	if err != nil {
		return fmt.Errorf("fleet: remove device: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("fleet: device %s not found", deviceID)
	}
	if aerr := r.auditLog.Record(context.Background(), audit.Event{
		Type:    audit.EventFleetRemove,
		Outcome: audit.OutcomeAllow,
		Target:  deviceID,
		Detail:  map[string]any{"device_id": deviceID},
	}); aerr != nil {
		return fmt.Errorf("fleet: refusing to remove device unaudited: %w", aerr)
	}
	return nil
}

// Get returns a device by ID.
func (r *Registry) Get(deviceID string) (*Device, error) {
	row := r.db.QueryRow(
		`SELECT device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata, ca_fingerprint, ca_cert_pem, revoked, revoked_at, reason
		 FROM fleet_devices WHERE device_id = ?`, deviceID,
	)
	return scanDevice(row)
}

// List returns all devices, optionally filtered by status.
func (r *Registry) List(statusFilter DeviceStatus) ([]Device, error) {
	var rows *sql.Rows
	var err error
	if statusFilter != "" {
		rows, err = r.db.Query(
			`SELECT device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata, ca_fingerprint, ca_cert_pem, revoked, revoked_at, reason
			 FROM fleet_devices WHERE status = ? ORDER BY last_seen_at DESC`, string(statusFilter),
		)
	} else {
		rows, err = r.db.Query(
			`SELECT device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata, ca_fingerprint, ca_cert_pem, revoked, revoked_at, reason
			 FROM fleet_devices ORDER BY last_seen_at DESC`,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("fleet: list devices: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var devices []Device
	for rows.Next() {
		d, err := scanDeviceRow(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

// UpdateLastSeen updates the last seen timestamp for a device.
func (r *Registry) UpdateLastSeen(deviceID string) error {
	_, err := r.db.Exec(
		`UPDATE fleet_devices SET last_seen_at = ?, status = ? WHERE device_id = ?`,
		time.Now().Unix(), string(StatusOnline), deviceID,
	)
	return err
}

// SetOffline marks a device as offline.
func (r *Registry) SetOffline(deviceID string) error {
	_, err := r.db.Exec(
		`UPDATE fleet_devices SET status = ? WHERE device_id = ?`,
		string(StatusOffline), deviceID,
	)
	return err
}

// IsTrusted returns true if the device is accepted (online or offline, not pending).
func (r *Registry) IsTrusted(deviceID string) bool {
	var status string
	err := r.db.QueryRow(
		`SELECT status FROM fleet_devices WHERE device_id = ?`, deviceID,
	).Scan(&status)
	if err != nil {
		return false
	}
	return status != string(StatusPending)
}

// Count returns the number of devices by status.
func (r *Registry) Count(statusFilter DeviceStatus) (int, error) {
	var count int
	var err error
	if statusFilter != "" {
		err = r.db.QueryRow(
			`SELECT COUNT(*) FROM fleet_devices WHERE status = ?`, string(statusFilter),
		).Scan(&count)
	} else {
		err = r.db.QueryRow(`SELECT COUNT(*) FROM fleet_devices`).Scan(&count)
	}
	return count, err
}

func scanDevice(row *sql.Row) (*Device, error) {
	d := &Device{}
	var lastSeen, created int64
	var meta string
	var revoked int
	var revokedAt, reason sql.NullString
	err := row.Scan(&d.DeviceID, &d.Hostname, &d.OS, &d.Arch, &d.Role, &d.Status, &d.Address, &d.CertPEM, &lastSeen, &created, &meta, &d.CAFingerprint, &d.CACertPEM, &revoked, &revokedAt, &reason)
	if err != nil {
		return nil, fmt.Errorf("fleet: scan device: %w", err)
	}
	d.LastSeenAt = time.Unix(lastSeen, 0)
	d.CreatedAt = time.Unix(created, 0)
	_ = json.Unmarshal([]byte(meta), &d.Metadata)
	d.Revoked = revoked != 0
	if revokedAt.Valid && revokedAt.String != "" {
		if ts, perr := time.Parse(time.RFC3339, revokedAt.String); perr == nil {
			d.RevokedAt = ts
		}
	}
	d.RevokedReason = reason.String
	return d, nil
}

func scanDeviceRow(rows *sql.Rows) (*Device, error) {
	d := &Device{}
	var lastSeen, created int64
	var meta string
	var revoked int
	var revokedAt, reason sql.NullString
	err := rows.Scan(&d.DeviceID, &d.Hostname, &d.OS, &d.Arch, &d.Role, &d.Status, &d.Address, &d.CertPEM, &lastSeen, &created, &meta, &d.CAFingerprint, &d.CACertPEM, &revoked, &revokedAt, &reason)
	if err != nil {
		return nil, fmt.Errorf("fleet: scan device row: %w", err)
	}
	d.LastSeenAt = time.Unix(lastSeen, 0)
	d.CreatedAt = time.Unix(created, 0)
	_ = json.Unmarshal([]byte(meta), &d.Metadata)
	d.Revoked = revoked != 0
	if revokedAt.Valid && revokedAt.String != "" {
		if ts, perr := time.Parse(time.RFC3339, revokedAt.String); perr == nil {
			d.RevokedAt = ts
		}
	}
	d.RevokedReason = reason.String
	return d, nil
}

// SetCAPin records the pinned CA fingerprint and certificate for a peer. The
// fingerprint pins the trust anchor agreed at pairing time so a later CA
// rotation is detectable. Returns an error if the device is not registered.
//
// When this REPLACES a different, already-pinned fingerprint (a genuine CA
// rotation) it emits the critical capin.change event and fails closed: if that
// audit write fails the pin is NOT changed. A first-time pin (no prior
// fingerprint) and a no-op re-pin (same fingerprint) do not emit capin.change.
func (r *Registry) SetCAPin(deviceID, fingerprint string, caCertPEM []byte) error {
	// Read the current pin first so a genuine rotation can be detected and
	// audited before the row is mutated (fail-closed ordering).
	var oldFingerprint string
	err := r.db.QueryRow(
		`SELECT ca_fingerprint FROM fleet_devices WHERE device_id = ?`, deviceID,
	).Scan(&oldFingerprint)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("fleet: device %s not found", deviceID)
		}
		return fmt.Errorf("fleet: read existing CA pin: %w", err)
	}

	rotated := oldFingerprint != "" && oldFingerprint != fingerprint
	if rotated {
		// Critical event: emit BEFORE changing the pin. On audit-write failure
		// the pin is left untouched so the rotation cannot be applied unrecorded.
		if aerr := r.auditLog.Record(context.Background(), audit.Event{
			Type:    audit.EventCAPinChange,
			Outcome: audit.OutcomeAllow,
			Target:  deviceID,
			Detail: map[string]any{
				"device_id":     deviceID,
				"old_fp_prefix": fingerprintPrefix(oldFingerprint),
				"new_fp_prefix": fingerprintPrefix(fingerprint),
			},
		}); aerr != nil {
			return fmt.Errorf("fleet: refusing to change CA pin unaudited: %w", aerr)
		}
	}

	res, err := r.db.Exec(
		`UPDATE fleet_devices SET ca_fingerprint = ?, ca_cert_pem = ? WHERE device_id = ?`,
		fingerprint, caCertPEM, deviceID,
	)
	if err != nil {
		return fmt.Errorf("fleet: set CA pin: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("fleet: device %s not found", deviceID)
	}
	return nil
}

// Revoke marks a device revoked and records the reason + timestamp. It emits the
// critical device.revoked audit event and fails closed: on audit-write failure
// the device is NOT revoked (so the action is never applied unrecorded).
func (r *Registry) Revoke(deviceID, reason string) error {
	if _, err := r.Get(deviceID); err != nil {
		return fmt.Errorf("fleet: revoke: %w", err)
	}
	if aerr := r.auditLog.Record(context.Background(), audit.Event{
		Type:    audit.EventDeviceRevoked,
		Outcome: audit.OutcomeAllow,
		Target:  deviceID,
		Detail:  map[string]any{"device_id": deviceID, "reason": reason},
	}); aerr != nil {
		return fmt.Errorf("fleet: refusing to revoke device unaudited: %w", aerr)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := r.db.Exec(
		`UPDATE fleet_devices SET revoked = 1, revoked_at = ?, reason = ? WHERE device_id = ?`,
		now, reason, deviceID,
	)
	if err != nil {
		return fmt.Errorf("fleet: revoke device: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("fleet: device %s not found", deviceID)
	}
	return nil
}

// Unrevoke clears a device's revoked state. It emits the critical
// device.unrevoked event and fails closed.
func (r *Registry) Unrevoke(deviceID string) error {
	if _, err := r.Get(deviceID); err != nil {
		return fmt.Errorf("fleet: unrevoke: %w", err)
	}
	if aerr := r.auditLog.Record(context.Background(), audit.Event{
		Type:    audit.EventDeviceUnrevoked,
		Outcome: audit.OutcomeAllow,
		Target:  deviceID,
		Detail:  map[string]any{"device_id": deviceID},
	}); aerr != nil {
		return fmt.Errorf("fleet: refusing to unrevoke device unaudited: %w", aerr)
	}
	res, err := r.db.Exec(
		`UPDATE fleet_devices SET revoked = 0, revoked_at = NULL, reason = NULL WHERE device_id = ?`,
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("fleet: unrevoke device: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("fleet: device %s not found", deviceID)
	}
	return nil
}

// IsRevoked reports whether the device is currently revoked. An unknown device
// is reported not-revoked (the handshake's CA/pin checks reject unknowns).
func (r *Registry) IsRevoked(deviceID string) bool {
	var revoked int
	if err := r.db.QueryRow(
		`SELECT revoked FROM fleet_devices WHERE device_id = ?`, deviceID,
	).Scan(&revoked); err != nil {
		return false
	}
	return revoked != 0
}

// fingerprintPrefix returns a short, non-secret prefix of a CA fingerprint for
// audit detail. Fingerprints are public certificate digests (not secrets), but
// only a prefix is recorded to keep audit detail compact and to avoid logging
// full identifiers as a matter of hygiene.
func fingerprintPrefix(fp string) string {
	const max = 19 // e.g. "sha256:" + 12 hex chars
	if len(fp) <= max {
		return fp
	}
	return fp[:max]
}
