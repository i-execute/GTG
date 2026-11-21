package updates

import (
	"context"
	"testing"

	"github.com/i-execute/GTG/entities"
	"github.com/i-execute/GTG/tl"
)

func TestTelegramEngineIngestsEnvelopeEntities(t *testing.T) {
	state, err := New(Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	cache := entities.New()
	engine, err := NewTelegramEngine(state, &fakeCaller{}, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope := tl.Dynamic{Name: "updates", Fields: map[string]any{
		"updates": []any{},
		"users":   []any{tl.Dynamic{Name: "user", Fields: map[string]any{"id": int64(1), "access_hash": int64(2), "username": "one"}}},
		"chats":   []any{},
		"date":    int32(1),
		"seq":     int32(0),
	}}
	if err := engine.Apply(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.PeerByUsername("one"); !ok {
		t.Fatal("envelope entity not ingested")
	}
}
