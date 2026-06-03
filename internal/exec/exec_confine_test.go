package exec

import (
	"context"
	"testing"

	"github.com/inovacc/sentinel/internal/confine"
)

func newConfinedRunner(t *testing.T, allow []string, c confine.Confiner) *Runner {
	t.Helper()
	r, _ := newTestRunner(t, allow) // from exec_test.go
	r.confiner = c
	return r
}

func TestRun_CallsConfiner(t *testing.T) {
	f := &confine.Fake{SupportedVal: true}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.Prepared == 0 || f.Confined == 0 {
		t.Errorf("Run must Prepare and Confine (prepared=%d confined=%d)", f.Prepared, f.Confined)
	}
}

func TestRun_FailClosedWhenSupportedConfineErrors(t *testing.T) {
	f := &confine.Fake{SupportedVal: true, ConfineErr: errConfine}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}}); err == nil {
		t.Fatal("a supported confiner that fails to confine must fail the exec closed")
	}
}

func TestRun_WarnsButProceedsWhenUnsupported(t *testing.T) {
	f := &confine.Fake{SupportedVal: false}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}}); err != nil {
		t.Fatalf("unsupported confiner must not block exec: %v", err)
	}
}

func TestRun_PrepareErrorFailsBuild(t *testing.T) {
	f := &confine.Fake{SupportedVal: true, PrepareErr: errConfine}
	r := newConfinedRunner(t, []string{"go"}, f)
	_, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}})
	if err == nil {
		t.Fatal("a Prepare error must abort buildCmd before the process is started")
	}
	if f.Prepared == 0 {
		t.Errorf("Prepare must have been attempted (prepared=%d)", f.Prepared)
	}
	if f.Confined != 0 {
		t.Errorf("Confine must not run when Prepare fails (confined=%d)", f.Confined)
	}
}

func TestRunBackground_CallsConfiner(t *testing.T) {
	f := &confine.Fake{SupportedVal: true}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}, Background: true}); err != nil {
		t.Fatalf("background Run: %v", err)
	}
	if f.Prepared == 0 || f.Confined == 0 {
		t.Errorf("background Run must Prepare and Confine (prepared=%d confined=%d)", f.Prepared, f.Confined)
	}
}

func TestRunBackground_FailClosedWhenSupportedConfineErrors(t *testing.T) {
	f := &confine.Fake{SupportedVal: true, ConfineErr: errConfine}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}, Background: true}); err == nil {
		t.Fatal("a supported confiner that fails to confine must fail the background exec closed")
	}
}

func TestRunStream_CallsConfiner(t *testing.T) {
	f := &confine.Fake{SupportedVal: true}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.RunStream(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}},
		func(string, []byte) {}); err != nil {
		t.Fatalf("RunStream: %v", err)
	}
	if f.Prepared == 0 || f.Confined == 0 {
		t.Errorf("RunStream must Prepare and Confine (prepared=%d confined=%d)", f.Prepared, f.Confined)
	}
}

func TestRunStream_FailClosedWhenSupportedConfineErrors(t *testing.T) {
	f := &confine.Fake{SupportedVal: true, ConfineErr: errConfine}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.RunStream(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}},
		func(string, []byte) {}); err == nil {
		t.Fatal("a supported confiner that fails to confine must fail the streamed exec closed")
	}
}

var errConfine = &confineErr{}

type confineErr struct{}

func (*confineErr) Error() string { return "confine failed" }
