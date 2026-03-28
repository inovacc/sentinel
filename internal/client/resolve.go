package client

import (
	"database/sql"
	"fmt"

	"github.com/inovacc/sentinel/internal/fleet"
)

// ResolveDevice looks up a device address from the fleet registry.
func ResolveDevice(deviceID string, dbPath string) (string, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return "", fmt.Errorf("resolve: open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	reg, err := fleet.NewRegistry(db)
	if err != nil {
		return "", fmt.Errorf("resolve: init registry: %w", err)
	}

	device, err := reg.Get(deviceID)
	if err != nil {
		return "", fmt.Errorf("resolve: device %q not found: %w", deviceID, err)
	}

	if device.Address == "" {
		return "", fmt.Errorf("resolve: device %q has no address", deviceID)
	}

	return device.Address, nil
}
