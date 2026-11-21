package entities

import (
	"testing"

	"github.com/i-execute/GTG/tl"
)

func TestIngestNestedEntitiesAndPeers(t *testing.T) {
	cache := New()
	value := tl.Dynamic{Name: "updates", Fields: map[string]any{
		"users": []any{
			tl.Dynamic{Name: "user", Fields: map[string]any{"id": int64(1), "access_hash": int64(2), "username": "Alice"}},
		},
		"chats": []any{
			tl.Dynamic{Name: "channel", Fields: map[string]any{"id": int64(3), "access_hash": int64(4), "username": "News"}},
		},
	}}
	if err := cache.Ingest(value); err != nil {
		t.Fatal(err)
	}
	user, ok := cache.PeerByUsername("@alice")
	if !ok || user.Name != "inputPeerUser" || user.Fields["user_id"] != int64(1) {
		t.Fatal("user peer mismatch")
	}
	channel, ok := cache.PeerByID(3)
	if !ok || channel.Name != "inputPeerChannel" || channel.Fields["access_hash"] != int64(4) {
		t.Fatal("channel peer mismatch")
	}
}

func TestIngestMinimumPreservesAccessHash(t *testing.T) {
	cache := New()
	if err := cache.Put(Entity{ID: 1, AccessHash: 9, Username: "name", Kind: User}); err != nil {
		t.Fatal(err)
	}
	if err := cache.Ingest(tl.Dynamic{Name: "user", Fields: map[string]any{"id": int64(1), "min": true}}); err != nil {
		t.Fatal(err)
	}
	value, ok := cache.GetID(1)
	if !ok || value.AccessHash != 9 || value.Username != "name" {
		t.Fatal("minimum merge mismatch")
	}
}
