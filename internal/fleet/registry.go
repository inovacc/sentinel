// Package fleet manages the device fleet registry with SQLite persistence.
package fleet

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
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
	DeviceID    string       `json:"device_id"`
	Hostname    string       `json:"hostname"`
	OS          string       `json:"os"`
	Arch        string       `json:"arch"`
	Role        string       `json:"role"`
	Status      DeviceStatus `json:"status"`
	Address     string       `json:"address"`
	CertPEM     []byte       `json:"-"`
	LastSeenAt  time.Time    `json:"last_seen_at"`
	CreatedAt   time.Time    `json:"created_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Registry manages the fleet of known devices.
type Registry struct {
	db *sql.DB
}

// NewRegistry creates a fleet registry with SQLite persistence.
func NewRegistry(db *sql.DB) (*Registry, error) {
	r := &Registry{db: db}
	if err := r.migrate(); err != nil {
		return nil, fmt.Errorf("fleet: migrate schema: %w", err)
	}
	return r, nil
}

func (r *Registry) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS fleet_devices (
    device_id    TEXT PRIMARY KEY,
    hostname     TEXT NOT NULL DEFAULT '',
    os           TEXT NOT NULL DEFAULT '',
    arch         TEXT NOT NULL DEFAULT '',
    role         TEXT NOT NULL DEFAULT 'reader',
    status       TEXT NOT NULL DEFAULT 'pending',
    address      TEXT NOT NULL DEFAULT '',
    cert_pem     BLOB,
    last_seen_at INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    metadata     TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_fleet_status ON fleet_devices(status);
`
	_, err := r.db.Exec(schema)
	return err
}

// AddPending adds a device as pending (awaiting approval).
func (r *Registry) AddPending(d *Device) error {
	meta, _ := json.Marshal(d.Metadata)
	now := time.Now().Unix()
	_, err := r.db.Exec(
		`INSERT OR REPLACE INTO fleet_devices (device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceID, d.Hostname, d.OS, d.Arch, d.Role, string(StatusPending), d.Address, d.CertPEM, now, now, string(meta),
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

// Remove removes any device from the registry.
func (r *Registry) Remove(deviceID string) error {
	res, err := r.db.Exec(`DELETE FROM fleet_devices WHERE device_id = ?`, deviceID)
	if err != nil {
		return fmt.Errorf("fleet: remove device: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("fleet: device %s not found", deviceID)
	}
	return nil
}

// Get returns a device by ID.
func (r *Registry) Get(deviceID string) (*Device, error) {
	row := r.db.QueryRow(
		`SELECT device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata
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
			`SELECT device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata
			 FROM fleet_devices WHERE status = ? ORDER BY last_seen_at DESC`, string(statusFilter),
		)
	} else {
		rows, err = r.db.Query(
			`SELECT device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata
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
	err := row.Scan(&d.DeviceID, &d.Hostname, &d.OS, &d.Arch, &d.Role, &d.Status, &d.Address, &d.CertPEM, &lastSeen, &created, &meta)
	if err != nil {
		return nil, fmt.Errorf("fleet: scan device: %w", err)
	}
	d.LastSeenAt = time.Unix(lastSeen, 0)
	d.CreatedAt = time.Unix(created, 0)
	_ = json.Unmarshal([]byte(meta), &d.Metadata)
	return d, nil
}

func scanDeviceRow(rows *sql.Rows) (*Device, error) {
	d := &Device{}
	var lastSeen, created int64
	var meta string
	err := rows.Scan(&d.DeviceID, &d.Hostname, &d.OS, &d.Arch, &d.Role, &d.Status, &d.Address, &d.CertPEM, &lastSeen, &created, &meta)
	if err != nil {
		return nil, fmt.Errorf("fleet: scan device row: %w", err)
	}
	d.LastSeenAt = time.Unix(lastSeen, 0)
	d.CreatedAt = time.Unix(created, 0)
	_ = json.Unmarshal([]byte(meta), &d.Metadata)
	return d, nil
}
