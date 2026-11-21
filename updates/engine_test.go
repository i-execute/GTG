package updates

import (
	"context"
	"testing"

	"github.com/i-execute/GTG/tl"
)

func TestEngineRecoversGapBeforeDispatch(t *testing.T) {
	state, err := New(Snapshot{PTS: 10, QTS: 2, Date: 3, Seq: 4})
	if err != nil {
		t.Fatal(err)
	}
	var fetched int
	var seen []string
	engine, err := NewEngine(state, func(ctx context.Context, from Snapshot) (Difference, error) {
		fetched++
		if from.PTS != 10 {
			t.Fatal("unexpected difference checkpoint")
		}
		return Difference{Updates: []tl.Dynamic{{Name: "difference", Fields: map[string]any{"pts": int32(11), "pts_count": int32(1)}}}, State: Snapshot{PTS: 11, QTS: 2, Date: 3, Seq: 4}, Final: true}, nil
	}, func(ctx context.Context, value tl.Dynamic) error {
		seen = append(seen, value.Name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(context.Background(), tl.Dynamic{Name: "update", Fields: map[string]any{"pts": int32(12), "pts_count": int32(1)}}); err != nil {
		t.Fatal(err)
	}
	if fetched != 1 || len(seen) != 2 || seen[0] != "difference" || seen[1] != "update" || state.Snapshot().PTS != 12 {
		t.Fatal("difference recovery mismatch")
	}
}

func TestEngineRejectsUnrecoverableGap(t *testing.T) {
	state, err := New(Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(state, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(context.Background(), tl.Dynamic{Name: "update", Fields: map[string]any{"pts": int32(2), "pts_count": int32(1)}}); err != ErrDifference {
		t.Fatalf("unexpected error %v", err)
	}
}
