package rbac

import (
	"errors"
	"testing"
)

func TestRoleLevel(t *testing.T) {
	cases := map[string]int{"admin": 3, "operator": 2, "reader": 1, "": 0, "superuser": 0}
	for role, want := range cases {
		if got := roleLevel(role); got != want {
			t.Errorf("roleLevel(%q) = %d, want %d", role, got, want)
		}
	}
}

func TestPolicyCheck(t *testing.T) {
	p := NewPolicy()
	tests := []struct {
		name    string
		method  string
		role    string
		allowed bool
	}{
		{"admin method + admin role", "/sentinel.v1.FleetService/Register", "admin", true},
		{"admin method + operator role denied", "/sentinel.v1.FleetService/Register", "operator", false},
		{"admin method + reader role denied", "/sentinel.v1.FleetService/Register", "reader", false},
		{"destroy is admin-gated, operator denied", "/sentinel.v1.SessionService/Destroy", "operator", false},

		{"operator method + admin role (higher ok)", "/sentinel.v1.ExecService/Exec", "admin", true},
		{"operator method + operator role", "/sentinel.v1.ExecService/Exec", "operator", true},
		{"exec is operator-gated, reader denied", "/sentinel.v1.ExecService/Exec", "reader", false},
		{"exec stream operator-gated, reader denied", "/sentinel.v1.ExecService/ExecStream", "reader", false},
		{"writefile operator-gated, reader denied", "/sentinel.v1.FileSystemService/WriteFile", "reader", false},

		{"reader method + reader role", "/sentinel.v1.FileSystemService/ReadFile", "reader", true},
		{"reader method + operator role (higher ok)", "/sentinel.v1.FileSystemService/ReadFile", "operator", true},
		{"reader method + admin role (higher ok)", "/sentinel.v1.FileSystemService/ReadFile", "admin", true},
		{"reader method + unknown role denied", "/sentinel.v1.FileSystemService/ReadFile", "", false},
		{"reader method + bogus role denied", "/sentinel.v1.FileSystemService/ReadFile", "wizard", false},

		{"unknown method denied even for admin (deny by default)", "/sentinel.v1.SecretService/Exfiltrate", "admin", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Check(tt.method, tt.role)
			if tt.allowed {
				if err != nil {
					t.Errorf("Check(%q, %q) = %v, want allowed", tt.method, tt.role, err)
				}
				return
			}
			if err == nil {
				t.Errorf("Check(%q, %q) = nil, want denied", tt.method, tt.role)
			} else if !errors.Is(err, ErrAccessDenied) {
				t.Errorf("denial should wrap ErrAccessDenied, got %v", err)
			}
		})
	}
}

func TestMinRole(t *testing.T) {
	p := NewPolicy()
	if got := p.MinRole("/sentinel.v1.ExecService/Exec"); got != "operator" {
		t.Errorf("MinRole(Exec) = %q, want operator", got)
	}
	if got := p.MinRole("/sentinel.v1.FleetService/Register"); got != "admin" {
		t.Errorf("MinRole(Register) = %q, want admin", got)
	}
	if got := p.MinRole("/totally/Unknown"); got != "" {
		t.Errorf("MinRole(unknown) = %q, want empty", got)
	}
}

// TestMinRoleWildcard exercises the service-level "/*" prefix rule branch, which
// the default policy does not use.
func TestMinRoleWildcard(t *testing.T) {
	p := &Policy{rules: map[string]string{"/sentinel.v1.DebugService/*": "admin"}}
	if got := p.MinRole("/sentinel.v1.DebugService/Anything"); got != "admin" {
		t.Errorf("wildcard prefix should match, got %q", got)
	}
	if got := p.MinRole("/sentinel.v1.OtherService/Method"); got != "" {
		t.Errorf("non-matching method should be empty, got %q", got)
	}
}
