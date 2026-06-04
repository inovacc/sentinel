package confine

import (
	"reflect"
	"testing"
)

func TestTrampolineArgsRoundTrip(t *testing.T) {
	c := Config{
		ProcMaxMemoryBytes: 1 << 30,
		ProcMaxOpenFiles:   1024,
		ProcMaxCPUSeconds:  0,
	}
	pre := trampolinePrefix(c)
	want := []string{
		TrampolineSubcommand,
		"--as", "1073741824",
		"--nofile", "1024",
		"--cpu", "0",
		"--",
	}
	if !reflect.DeepEqual(pre, want) {
		t.Fatalf("trampolinePrefix = %v, want %v", pre, want)
	}
}

func TestParseTrampolineRlimits(t *testing.T) {
	as, nofile, cpu, rest, err := ParseTrampolineArgs([]string{
		"--as", "5", "--nofile", "6", "--cpu", "7", "--", "echo", "hi",
	})
	if err != nil {
		t.Fatalf("ParseTrampolineArgs: %v", err)
	}
	if as != 5 || nofile != 6 || cpu != 7 {
		t.Fatalf("limits = %d/%d/%d, want 5/6/7", as, nofile, cpu)
	}
	if !reflect.DeepEqual(rest, []string{"echo", "hi"}) {
		t.Fatalf("rest = %v", rest)
	}
}
