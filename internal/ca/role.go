package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// RoleOID is the custom OID for the sentinel role extension.
var RoleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

// Roles
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleReader   = "reader"
)

// ValidRole checks if the given role is valid.
func ValidRole(role string) bool {
	switch role {
	case RoleAdmin, RoleOperator, RoleReader:
		return true
	default:
		return false
	}
}

// ExtractRole extracts the role from a certificate's custom extension.
func ExtractRole(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(RoleOID) {
			var role string
			rest, err := asn1.Unmarshal(ext.Value, &role)
			if err != nil {
				return "", fmt.Errorf("ca: unmarshal role extension: %w", err)
			}
			if len(rest) > 0 {
				return "", fmt.Errorf("ca: trailing data in role extension")
			}
			if !ValidRole(role) {
				return "", fmt.Errorf("ca: unknown role %q in certificate", role)
			}
			return role, nil
		}
	}
	return "", fmt.Errorf("ca: role extension not found")
}

// roleExtension creates the X.509 extension for a role.
func roleExtension(role string) pkix.Extension {
	val, _ := asn1.Marshal(role)
	return pkix.Extension{
		Id:    RoleOID,
		Value: val,
	}
}
