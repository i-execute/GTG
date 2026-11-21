package updates

import (
	"context"
	"testing"

	"github.com/i-execute/GTG/entities"
	"github.com/i-execute/GTG/tl"
)

type fakeCaller struct {
	requests []tl.Dynamic
	results  []tl.Dynamic
}

func (x *fakeCaller) Call(ctx context.Context, request tl.Dynamic) (tl.Dynamic, error) {
	x.requests = append(x.requests, request)
	result := x.results[0]
	x.results = x.results[1:]
	return result, nil
}

func telegramStateValue(pts, qts, date, sequence int32) tl.Dynamic {
	return tl.Dynamic{Name: "updates.state", Fields: map[string]any{"pts": pts, "qts": qts, "date": date, "seq": sequence}}
}

func TestTelegramFetcherDifferenceAndEntities(t *testing.T) {
	caller := &fakeCaller{results: []tl.Dynamic{{Name: "updates.difference", Fields: map[string]any{
		"other_updates": []any{tl.Dynamic{Name: "updateNewMessage", Fields: map[string]any{"pts": int32(11), "pts_count": int32(1)}}},
		"users":         []any{tl.Dynamic{Name: "user", Fields: map[string]any{"id": int64(3), "access_hash": int64(4), "username": "Three"}}},
		"state":         telegramStateValue(11, 2, 3, 4),
	}}}}
	cache := entities.New()
	fetch := NewTelegramFetcher(caller, cache)
	difference, err := fetch(context.Background(), Snapshot{PTS: 10, QTS: 2, Date: 3, Seq: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(caller.requests) != 1 || caller.requests[0].Name != "updates.getDifference" || caller.requests[0].Fields["pts"] != int32(10) {
		t.Fatal("difference request mismatch")
	}
	if !difference.Final || len(difference.Updates) != 1 || difference.State.PTS != 11 {
		t.Fatal("difference parse mismatch")
	}
	if _, ok := cache.PeerByUsername("three"); !ok {
		t.Fatal("difference entities not ingested")
	}
}

func TestTelegramFetcherTooLongGetsState(t *testing.T) {
	caller := &fakeCaller{results: []tl.Dynamic{
		{Name: "updates.differenceTooLong", Fields: map[string]any{"pts": int32(99)}},
		telegramStateValue(99, 7, 8, 9),
	}}
	fetch := NewTelegramFetcher(caller, nil)
	difference, err := fetch(context.Background(), Snapshot{PTS: 1})
	if err != nil || !difference.Final || difference.State.PTS != 99 || len(caller.requests) != 2 || caller.requests[1].Name != "updates.getState" {
		t.Fatal("too long state recovery mismatch")
	}
}

func TestTelegramEngineRecoversTypedDifference(t *testing.T) {
	state, err := New(Snapshot{PTS: 10})
	if err != nil {
		t.Fatal(err)
	}
	caller := &fakeCaller{results: []tl.Dynamic{{Name: "updates.difference", Fields: map[string]any{
		"other_updates": []any{tl.Dynamic{Name: "updateFromDifference", Fields: map[string]any{"pts": int32(11), "pts_count": int32(1)}}},
		"state":         telegramStateValue(11, 0, 0, 0),
	}}}}
	var seen []string
	engine, err := NewTelegramEngine(state, caller, entities.New(), func(ctx context.Context, value tl.Dynamic) error {
		seen = append(seen, value.Name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(context.Background(), tl.Dynamic{Name: "updateCurrent", Fields: map[string]any{"pts": int32(12), "pts_count": int32(1)}}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "updateFromDifference" || seen[1] != "updateCurrent" || state.Snapshot().PTS != 12 {
		t.Fatal("engine recovery mismatch")
	}
}
