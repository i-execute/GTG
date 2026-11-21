package api

import (
	"context"
	"testing"

	"github.com/i-execute/GTG/tl"
)

type capture struct {
	value tl.Dynamic
}

func (x *capture) Call(_ context.Context, value tl.Dynamic) (tl.Dynamic, error) {
	x.value = value
	return tl.Dynamic{Name: "ok", Fields: map[string]any{}}, nil
}

func TestSavedMessagesOnlyAndReads(t *testing.T) {
	capture := &capture{}
	client, err := New(capture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendSaved(t.Context(), "hello"); err != nil {
		t.Fatal(err)
	}
	peer, ok := capture.value.Fields["peer"].(tl.Dynamic)
	if !ok || peer.Name != "inputPeerSelf" || capture.value.Name != "messages.sendMessage" {
		t.Fatal("send target is not Saved Messages")
	}
	if _, err := client.SavedHistory(t.Context(), 0, 10); err != nil || capture.value.Name != "messages.getHistory" {
		t.Fatal(err)
	}
	if _, err := client.Dialogs(t.Context(), 10); err != nil || capture.value.Name != "messages.getDialogs" {
		t.Fatal(err)
	}
}

func TestEscapeMarkdownV2(t *testing.T) {
	if got := EscapeMarkdownV2("a_b!"); got != "a\\_b\\!" {
		t.Fatal(got)
	}
}
