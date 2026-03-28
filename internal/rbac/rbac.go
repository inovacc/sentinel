package rbac

import (
	"errors"
	"fmt"
	"strings"
)

// ErrAccessDenied is returned when a role lacks permission for a method.
var ErrAccessDenied = errors.New("rbac: access denied")

// Policy defines which roles can access which gRPC methods.
type Policy struct {
	rules map[string]string // method full name -> minimum role required
}

// NewPolicy creates a policy with default rules mapping all sentinel gRPC
// methods to their minimum required role.
func NewPolicy() *Policy {
	p := &Policy{
		rules: map[string]string{
			// Admin only
			"/sentinel.v1.FleetService/Register":     "admin",
			"/sentinel.v1.FleetService/AcceptPairing": "admin",
			"/sentinel.v1.SessionService/Destroy":     "admin",

			// Operator (operator + admin)
			"/sentinel.v1.ExecService/Exec":              "operator",
			"/sentinel.v1.ExecService/ExecStream":        "operator",
			"/sentinel.v1.FileSystemService/WriteFile":    "operator",
			"/sentinel.v1.FileSystemService/Upload":       "operator",
			"/sentinel.v1.FileSystemService/Delete":       "operator",
			"/sentinel.v1.SessionService/Create":          "operator",
			"/sentinel.v1.SessionService/Resume":          "operator",
			"/sentinel.v1.SessionService/Pause":           "operator",
			"/sentinel.v1.SessionService/Checkpoint":      "operator",

			// Reader (reader + operator + admin)
			"/sentinel.v1.FileSystemService/ReadFile":    "reader",
			"/sentinel.v1.FileSystemService/ListDir":     "reader",
			"/sentinel.v1.FileSystemService/Download":    "reader",
			"/sentinel.v1.FileSystemService/Glob":        "reader",
			"/sentinel.v1.FileSystemService/Grep":        "reader",
			"/sentinel.v1.FleetService/ListDevices":      "reader",
			"/sentinel.v1.FleetService/DeviceStatus":     "reader",
			"/sentinel.v1.FleetService/Health":           "reader",
			"/sentinel.v1.CaptureService/StartCapture":   "reader",
			"/sentinel.v1.CaptureService/StopCapture":    "reader",
			"/sentinel.v1.CaptureService/CaptureStatus":  "reader",
			"/sentinel.v1.CaptureService/ListCaptures":   "reader",
			"/sentinel.v1.SessionService/Status":          "reader",
			"/sentinel.v1.SessionService/List":            "reader",
			"/sentinel.v1.SessionService/Heartbeat":       "reader",
		},
	}
	return p
}

// Check verifies that the given role can access the method.
// Returns ErrAccessDenied with details on failure.
func (p *Policy) Check(method, role string) error {
	minRole := p.MinRole(method)
	if minRole == "" {
		// Unknown method: deny by default.
		return fmt.Errorf("%w: unknown method %q", ErrAccessDenied, method)
	}

	if roleLevel(role) < roleLevel(minRole) {
		return fmt.Errorf("%w: role %q cannot access %q (requires %q)", ErrAccessDenied, role, method, minRole)
	}
	return nil
}

// MinRole returns the minimum role required for a method.
// Returns empty string if the method is not in the policy.
func (p *Policy) MinRole(method string) string {
	if r, ok := p.rules[method]; ok {
		return r
	}

	// Wildcard match: check if any prefix matches (for service-level wildcards).
	for rule, role := range p.rules {
		if strings.HasSuffix(rule, "/*") {
			prefix := strings.TrimSuffix(rule, "*")
			if strings.HasPrefix(method, prefix) {
				return role
			}
		}
	}
	return ""
}

// roleLevel returns the numeric level for a role.
// admin=3, operator=2, reader=1, unknown=0.
func roleLevel(role string) int {
	switch role {
	case "admin":
		return 3
	case "operator":
		return 2
	case "reader":
		return 1
	default:
		return 0
	}
}
