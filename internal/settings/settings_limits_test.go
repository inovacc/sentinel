package settings

import "testing"

func TestDefaultLimitsConfig(t *testing.T) {
	c := DefaultConfig()
	l := c.Limits
	if !l.Enabled {
		t.Fatal("limits should default to enabled")
	}
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"BootstrapPerIPMaxConns", uint64(l.BootstrapPerIPMaxConns), 8},
		{"BootstrapPerIPRate", uint64(l.BootstrapPerIPRate), 5},
		{"MaxConns", uint64(l.MaxConns), 256},
		{"PerDeviceMaxConns", uint64(l.PerDeviceMaxConns), 16},
		{"MaxRecvMsgBytes", uint64(l.MaxRecvMsgBytes), 1048576},
		{"MaxConcurrentStreams", uint64(l.MaxConcurrentStreams), 128},
		{"RPCRatePerSec", uint64(l.RPCRatePerSec), 100},
		{"ProcMaxMemoryBytes", l.ProcMaxMemoryBytes, 1 << 30},
		{"ProcMaxOpenFiles", l.ProcMaxOpenFiles, 1024},
		{"ProcMaxCPUSeconds", l.ProcMaxCPUSeconds, 0},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
	if l.TLSHandshakeTimeout != 10_000_000_000 { // 10s
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", l.TLSHandshakeTimeout)
	}
}

func TestValidateLimits(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*LimitsConfig)
		wantErr bool
	}{
		{"defaults ok", func(*LimitsConfig) {}, false},
		{"disabled skips checks", func(l *LimitsConfig) { l.Enabled = false; l.MaxConns = 0 }, false},
		{"zero max conns", func(l *LimitsConfig) { l.MaxConns = 0 }, true},
		{"zero per-device", func(l *LimitsConfig) { l.PerDeviceMaxConns = 0 }, true},
		{"zero bootstrap conns", func(l *LimitsConfig) { l.BootstrapPerIPMaxConns = 0 }, true},
		{"zero recv bytes", func(l *LimitsConfig) { l.MaxRecvMsgBytes = 0 }, true},
		{"zero streams", func(l *LimitsConfig) { l.MaxConcurrentStreams = 0 }, true},
		{"zero rpc rate", func(l *LimitsConfig) { l.RPCRatePerSec = 0 }, true},
		{"zero handshake timeout", func(l *LimitsConfig) { l.TLSHandshakeTimeout = 0 }, true},
		{"zero proc mem ok (unlimited)", func(l *LimitsConfig) { l.ProcMaxMemoryBytes = 0 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.mutate(&c.Limits)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMigrateV3ToV4AddsLimits(t *testing.T) {
	c := DefaultConfig()
	c.Version = 3
	c.Limits = LimitsConfig{} // simulate a v3 file with no limits block
	changed := c.Migrate(3)
	if !changed {
		t.Fatal("Migrate(3) should report a change")
	}
	if c.Version != CurrentConfigVersion {
		t.Fatalf("Version = %d, want %d", c.Version, CurrentConfigVersion)
	}
	if !c.Limits.Enabled || c.Limits.MaxConns != 256 {
		t.Fatalf("Migrate did not back-fill limits defaults: %+v", c.Limits)
	}
}
