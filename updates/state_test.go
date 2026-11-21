package updates

import (
	"errors"
	"sync"
	"testing"

	"github.com/i-execute/GTG/vault"
)

func TestStateGapRecoveryAndVault(t *testing.T) {
	state, err := New(Snapshot{PTS: 10, QTS: 1, Date: 2, Seq: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyPTS(13, 3); err != nil {
		t.Fatal(err)
	}
	var gap *Gap
	if err := state.ApplyPTS(17, 3); !errors.As(err, &gap) {
		t.Fatal(err)
	}
	if err := state.ApplyQTS(4); err != nil {
		t.Fatal(err)
	}
	if err := state.ApplySeq(4, 9); err != nil {
		t.Fatal(err)
	}
	target := vault.New()
	if err := state.Store(target, "main"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(target, "main")
	if err != nil || loaded.Snapshot() != state.Snapshot() {
		t.Fatal(err)
	}
	target.Destroy()
}

func TestStateConcurrentMonotonicity(t *testing.T) {
	state, err := New(Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for value := worker; value < 500; value += 16 {
				_ = state.ApplyQTS(value)
			}
		}(worker)
	}
	group.Wait()
	if state.Snapshot().QTS != 499 {
		t.Fatal(state.Snapshot())
	}
}
