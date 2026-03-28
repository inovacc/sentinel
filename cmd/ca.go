package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/spf13/cobra"
)

func newCACmd() *cobra.Command {
	caCmd := &cobra.Command{
		Use:   "ca",
		Short: "Certificate Authority management",
	}

	caCmd.AddCommand(
		newCAInitCmd(),
		newCAShowCmd(),
		newCAExportCmd(),
		newCASignCmd(),
	)

	return caCmd
}

func newCAInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize a new CA (generates root certificate and key)",
		RunE: func(cmd *cobra.Command, args []string) error {
			caDir, err := datadir.CADir()
			if err != nil {
				return fmt.Errorf("ca dir: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Initializing CA in %s\n", caDir)

			authority, err := ca.Init(caDir)
			if err != nil {
				return fmt.Errorf("init CA: %w", err)
			}

			certPEM, keyPEM, err := authority.SignDevice(ca.RoleAdmin)
			if err != nil {
				return fmt.Errorf("sign device: %w", err)
			}

			certDir, err := datadir.CertDir()
			if err != nil {
				return fmt.Errorf("cert dir: %w", err)
			}

			if err := os.WriteFile(filepath.Join(certDir, "device.crt"), certPEM, 0o644); err != nil {
				return fmt.Errorf("write device cert: %w", err)
			}
			if err := os.WriteFile(filepath.Join(certDir, "device.key"), keyPEM, 0o600); err != nil {
				return fmt.Errorf("write device key: %w", err)
			}

			deviceID, err := ca.DeviceID(certPEM)
			if err != nil {
				return fmt.Errorf("compute device ID: %w", err)
			}

			block, _ := pem.Decode(certPEM)
			if block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					fmt.Fprintf(os.Stderr, "Device cert expires: %s\n", cert.NotAfter.Format("2006-01-02"))
				}
			}

			fmt.Fprintf(os.Stderr, "CA initialized successfully\n")
			fmt.Fprintf(os.Stderr, "Device ID: %s\n", deviceID)
			fmt.Fprintf(os.Stderr, "Role: %s\n", ca.RoleAdmin)
			fmt.Fprintf(os.Stderr, "Cert dir: %s\n", certDir)
			return nil
		},
	}
}

func newCAShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show CA and device certificate info",
		RunE: func(cmd *cobra.Command, args []string) error {
			caDir, err := datadir.CADir()
			if err != nil {
				return fmt.Errorf("ca dir: %w", err)
			}

			authority, err := ca.Load(caDir)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			caBlock, _ := pem.Decode(authority.RootCertPEM())
			if caBlock != nil {
				if caCert, err := x509.ParseCertificate(caBlock.Bytes); err == nil {
					fmt.Printf("CA Subject:  %s\n", caCert.Subject.CommonName)
					fmt.Printf("CA Expires:  %s\n", caCert.NotAfter.Format("2006-01-02"))
				}
			}

			certDir, err := datadir.CertDir()
			if err != nil {
				return fmt.Errorf("cert dir: %w", err)
			}

			certPEM, err := os.ReadFile(filepath.Join(certDir, "device.crt"))
			if err != nil {
				return fmt.Errorf("read device cert: %w", err)
			}

			deviceID, err := ca.DeviceID(certPEM)
			if err != nil {
				return fmt.Errorf("compute device ID: %w", err)
			}

			block, _ := pem.Decode(certPEM)
			if block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					role, _ := ca.ExtractRole(cert)
					fmt.Printf("Device ID:   %s\n", deviceID)
					fmt.Printf("Role:        %s\n", role)
					fmt.Printf("Expires:     %s\n", cert.NotAfter.Format("2006-01-02"))
					fmt.Printf("Subject:     %s\n", cert.Subject.CommonName)
				}
			}

			return nil
		},
	}
}

func newCAExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export [output-dir]",
		Short: "Export CA certificate for sharing with other devices",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			caDir, err := datadir.CADir()
			if err != nil {
				return fmt.Errorf("ca dir: %w", err)
			}

			authority, err := ca.Load(caDir)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			outputDir := "."
			if len(args) > 0 {
				outputDir = args[0]
			}

			outPath := filepath.Join(outputDir, "sentinel-ca.crt")
			if err := os.WriteFile(outPath, authority.RootCertPEM(), 0o644); err != nil {
				return fmt.Errorf("write CA cert: %w", err)
			}

			fmt.Fprintf(os.Stderr, "CA certificate exported to %s\n", outPath)
			return nil
		},
	}
}

func newCASignCmd() *cobra.Command {
	signCmd := &cobra.Command{
		Use:   "sign [csr-path]",
		Short: "Sign a certificate signing request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, _ := cmd.Flags().GetString("role")

			caDir, err := datadir.CADir()
			if err != nil {
				return fmt.Errorf("ca dir: %w", err)
			}

			authority, err := ca.Load(caDir)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			csrPEM, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read CSR: %w", err)
			}

			signedCert, err := authority.SignCSR(csrPEM, role)
			if err != nil {
				return fmt.Errorf("sign CSR: %w", err)
			}

			_, _ = fmt.Fprint(os.Stdout, string(signedCert))
			fmt.Fprintf(os.Stderr, "Signed certificate with role: %s\n", role)
			return nil
		},
	}

	signCmd.Flags().StringP("role", "r", "operator", "Role to embed: admin, operator, reader")
	return signCmd
}
