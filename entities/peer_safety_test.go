package entities

import "testing"

func TestInputPeerRejectsMissingAccessHash(t *testing.T) {
	for _, value := range []Entity{{ID: 1, Kind: User}, {ID: 2, Kind: Channel}} {
		if _, err := InputPeer(value); err != ErrEntity {
			t.Fatal("peer accepted absent access hash")
		}
	}
	peer, err := InputPeer(Entity{ID: 3, Kind: Chat})
	if err != nil || peer.Name != "inputPeerChat" {
		t.Fatal("chat peer mismatch")
	}
}
