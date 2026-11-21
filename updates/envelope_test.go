package updates

import (
	"context"
	"errors"
	"testing"

	"github.com/i-execute/GTG/tl"
)

func TestStateSequenceRange(t *testing.T) {
	state, err := New(Snapshot{Seq: 4, Date: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ApplySeqRange(5, 7, 8); err != nil || state.Snapshot().Seq != 7 || state.Snapshot().Date != 8 {
		t.Fatal("sequence range mismatch")
	}
	var gap *Gap
	if err := state.ApplySeqRange(9, 9, 9); !errors.As(err, &gap) || gap.WantFrom != 8 {
		t.Fatal("missing sequence range gap")
	}
}

func TestEngineExpandsUpdateEnvelope(t *testing.T) {
	state, err := New(Snapshot{PTS: 10, Seq: 4})
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	engine, err := NewEngine(state, nil, func(ctx context.Context, value tl.Dynamic) error {
		seen = append(seen, value.Name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := tl.Dynamic{Name: "updatesCombined", Fields: map[string]any{
		"updates":   []any{tl.Dynamic{Name: "updateOne", Fields: map[string]any{"pts": int32(11), "pts_count": int32(1)}}, tl.Dynamic{Name: "updateTwo", Fields: map[string]any{"pts": int32(12), "pts_count": int32(1)}}},
		"date":      int32(9),
		"seq_start": int32(5),
		"seq":       int32(6),
	}}
	if err := engine.Apply(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "updateOne" || seen[1] != "updateTwo" || state.Snapshot() != (Snapshot{PTS: 12, Date: 9, Seq: 6}) {
		t.Fatal("envelope expansion mismatch")
	}
}

func TestEngineExpandsShortUpdate(t *testing.T) {
	state, err := New(Snapshot{PTS: 10, Date: 1})
	if err != nil {
		t.Fatal(err)
	}
	var seen string
	engine, err := NewEngine(state, nil, func(ctx context.Context, value tl.Dynamic) error {
		seen = value.Name
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(context.Background(), tl.Dynamic{Name: "updateShort", Fields: map[string]any{"update": tl.Dynamic{Name: "updateOne", Fields: map[string]any{"pts": int32(11), "pts_count": int32(1)}}, "date": int32(2)}}); err != nil {
		t.Fatal(err)
	}
	if seen != "updateOne" || state.Snapshot() != (Snapshot{PTS: 11, Date: 2}) {
		t.Fatal("short update expansion mismatch")
	}
}
