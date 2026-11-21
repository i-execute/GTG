package entities

import (
	"testing"

	"github.com/i-execute/GTG/vault"
)

func TestCacheResolutionReplacementAndVault(t *testing.T) {
	cache := New()
	if err := cache.Put(Entity{ID: 7, AccessHash: 9, Username: "@First", Kind: User}); err != nil {
		t.Fatal(err)
	}
	if value, ok := cache.GetUsername("first"); !ok || value.ID != 7 {
		t.Fatal("username missing")
	}
	if err := cache.Put(Entity{ID: 7, AccessHash: 10, Username: "Second", Kind: User}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.GetUsername("first"); ok {
		t.Fatal("old username retained")
	}
	if value, ok := cache.GetUsername("@SECOND"); !ok || value.AccessHash != 10 {
		t.Fatal("new username missing")
	}
	target := vault.New()
	if err := cache.Store(target, "primary"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(target, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := loaded.GetID(7); !ok || value.Username != "second" {
		t.Fatal("loaded value missing")
	}
	target.Destroy()
}
