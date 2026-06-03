// internal/worker/pool_confine_test.go
package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/sentinel/internal/confine"
)

var errConfineWorker = errors.New("confine failed")

func TestSpawn_CallsConfiner(t *testing.T) {
	f := &confine.Fake{SupportedVal: true}
	p, _, _ := newTestPool(t, []string{"go"}, WithConfiner(f))
	if _, err := p.Spawn(context.Background(), "go", []string{"version"}, "", nil, "", nil, 0); err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if f.Prepared == 0 || f.Confined == 0 {
		t.Errorf("Spawn must Prepare and Confine (prepared=%d confined=%d)", f.Prepared, f.Confined)
	}
}

func TestSpawn_FailClosedOnConfineError(t *testing.T) {
	f := &confine.Fake{SupportedVal: true, ConfineErr: errConfineWorker}
	p, _, _ := newTestPool(t, []string{"go"}, WithConfiner(f))
	if _, err := p.Spawn(context.Background(), "go", []string{"version"}, "", nil, "", nil, 0); err == nil {
		t.Fatal("a supported confiner that fails must fail the spawn closed")
	}
}

func TestSpawn_PrepareErrorFailsBeforeStart(t *testing.T) {
	f := &confine.Fake{SupportedVal: true, PrepareErr: errConfineWorker}
	p, _, _ := newTestPool(t, []string{"go"}, WithConfiner(f))
	_, err := p.Spawn(context.Background(), "go", []string{"version"}, "", nil, "", nil, 0)
	if err == nil {
		t.Fatal("a Prepare error must abort the spawn before cmd.Start")
	}
	if f.Prepared == 0 {
		t.Errorf("Prepare must have been attempted (prepared=%d)", f.Prepared)
	}
	if f.Confined != 0 {
		t.Errorf("Confine must not run when Prepare fails (confined=%d)", f.Confined)
	}
}

func TestSpawn_WarnsButProceedsWhenUnsupported(t *testing.T) {
	f := &confine.Fake{SupportedVal: false}
	p, _, _ := newTestPool(t, []string{"go"}, WithConfiner(f))
	w, err := p.Spawn(context.Background(), "go", []string{"version"}, "", nil, "", nil, 0)
	if err != nil {
		t.Fatalf("unsupported confiner must not block spawn: %v", err)
	}
	if w == nil {
		t.Fatal("spawn must return a running worker when confinement is unsupported")
	}
	if f.Confined == 0 {
		t.Errorf("Confine must still be attempted on an unsupported platform (confined=%d)", f.Confined)
	}
}
