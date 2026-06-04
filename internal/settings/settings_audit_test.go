package settings

import "testing"

func TestCurrentConfigVersionIsThree(t *testing.T) {
	if CurrentConfigVersion != 3 {
		t.Fatalf("CurrentConfigVersion = %d, want 3", CurrentConfigVersion)
	}
}

func TestDefaultConfigHasAuditDefaults(t *testing.T) {
	c := DefaultConfig()
	if !c.Audit.Enabled {
		t.Error("audit should default enabled")
	}
	if c.Audit.RetentionDays != 90 {
		t.Errorf("audit retention_days default = %d, want 90", c.Audit.RetentionDays)
	}
	if c.Audit.SegmentMax != 10000 {
		t.Errorf("audit segment_max default = %d, want 10000", c.Audit.SegmentMax)
	}
}

func TestValidateRejectsBadAudit(t *testing.T) {
	c := DefaultConfig()
	c.Audit.RetentionDays = -1
	if err := c.Validate(); err == nil {
		t.Error("expected error for negative retention_days")
	}
	c = DefaultConfig()
	c.Audit.SegmentMax = 0
	if err := c.Validate(); err == nil {
		t.Error("expected error for segment_max < 1")
	}
}

func TestMigrateV2ToV3BumpsVersion(t *testing.T) {
	c := DefaultConfig()
	c.Version = 2
	changed := c.Migrate(2)
	if !changed {
		t.Error("Migrate(2) should report a change")
	}
	if c.Version != 3 {
		t.Errorf("post-migrate version = %d, want 3", c.Version)
	}
}
