package settings

import (
	"testing"
	"time"
)

func TestDefaultCryptoConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Crypto.KeyEncryption != "keystore" {
		t.Fatalf("default KeyEncryption = %q, want keystore", c.Crypto.KeyEncryption)
	}
	if c.Crypto.CertValidity != 720*time.Hour {
		t.Fatalf("default CertValidity = %v, want 720h", c.Crypto.CertValidity)
	}
	if c.Crypto.RenewThreshold != 240*time.Hour {
		t.Fatalf("default RenewThreshold = %v, want 240h", c.Crypto.RenewThreshold)
	}
	if c.Crypto.PassphraseEnv != "SENTINEL_CA_PASSPHRASE" {
		t.Fatalf("default PassphraseEnv = %q", c.Crypto.PassphraseEnv)
	}
}

func TestValidateCryptoRejectsBadMode(t *testing.T) {
	c := DefaultConfig()
	c.Crypto.KeyEncryption = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid key_encryption mode")
	}
}

func TestValidateCryptoRequiresPassphraseFile(t *testing.T) {
	c := DefaultConfig()
	c.Crypto.KeyEncryption = "passphrase-file"
	c.Crypto.PassphraseFile = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: passphrase-file mode needs a path")
	}
}

func TestValidateCryptoDurations(t *testing.T) {
	c := DefaultConfig()
	c.Crypto.RenewThreshold = c.Crypto.CertValidity // must be strictly less
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: renew_threshold must be < cert_validity")
	}
	c = DefaultConfig()
	c.Crypto.CertValidity = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: cert_validity must be > 0")
	}
	c = DefaultConfig()
	c.Crypto.CertValidity = 365 * 24 * time.Hour // > 90d hard max
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: cert_validity above max")
	}
}

func TestMigrateV4ToV5AddsCrypto(t *testing.T) {
	c := DefaultConfig()
	c.Version = 4
	c.Crypto = CryptoConfig{} // simulate a v4 file with no crypto block
	changed := c.Migrate(4)
	if !changed {
		t.Fatal("expected migration to change the config")
	}
	if c.Version != CurrentConfigVersion {
		t.Fatalf("version not bumped: %d", c.Version)
	}
	if c.Crypto.KeyEncryption != "keystore" {
		t.Fatal("v4->v5 migration must back-fill crypto defaults")
	}
}
