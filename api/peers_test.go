package api

import (
	"context"
	"testing"

	"github.com/i-execute/GTG/entities"
	"github.com/i-execute/GTG/tl"
)

type sequenceCapture struct {
	requests []tl.Dynamic
	results  []tl.Dynamic
}

func (x *sequenceCapture) Call(ctx context.Context, value tl.Dynamic) (tl.Dynamic, error) {
	x.requests = append(x.requests, value)
	result := x.results[0]
	x.results = x.results[1:]
	return result, nil
}

func TestSendToCachedPeer(t *testing.T) {
	cache := entities.New()
	if err := cache.Put(entities.Entity{ID: 7, AccessHash: 8, Kind: entities.User}); err != nil {
		t.Fatal(err)
	}
	capture := &sequenceCapture{results: []tl.Dynamic{{Name: "updates", Fields: map[string]any{}}}}
	client, err := NewWithEntities(capture, cache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendTo(context.Background(), 7, "hello"); err != nil {
		t.Fatal(err)
	}
	request := capture.requests[0]
	peer := request.Fields["peer"].(tl.Dynamic)
	if request.Name != "messages.sendMessage" || peer.Name != "inputPeerUser" || peer.Fields["access_hash"] != int64(8) {
		t.Fatal("cached peer send mismatch")
	}
}

func TestResolveUsernameIngestsAndSends(t *testing.T) {
	capture := &sequenceCapture{results: []tl.Dynamic{
		{Name: "contacts.resolvedPeer", Fields: map[string]any{"users": []any{tl.Dynamic{Name: "user", Fields: map[string]any{"id": int64(7), "access_hash": int64(8), "username": "name"}}}}},
		{Name: "updates", Fields: map[string]any{}},
	}}
	client, err := NewWithEntities(capture, entities.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendToUsername(context.Background(), "@name", "hello"); err != nil {
		t.Fatal(err)
	}
	if len(capture.requests) != 2 || capture.requests[0].Name != "contacts.resolveUsername" || capture.requests[1].Name != "messages.sendMessage" {
		t.Fatal("username resolution call sequence mismatch")
	}
}
