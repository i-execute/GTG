package core

import (
	"errors"
	"testing"
)

func TestMTProtoInPlaceAuthenticationErrorsAreUniform(t *testing.T) {
	key := makePattern(256, 91)
	box, err := NewMTProto(key)
	if err != nil {
		t.Fatal(err)
	}
	defer box.Destroy()
	packet := make([]byte, 24+64, 24+64+1024)
	copy(packet[24:], makePattern(64, 92))
	sealed, err := box.SealInPlace(packet, ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 8, len(sealed) - 1} {
		altered := append([]byte(nil), sealed...)
		altered[offset] ^= 1
		if _, err := box.OpenInPlace(altered, ClientToServer); !errors.Is(err, ErrMTProtoPacket) {
			t.Fatalf("offset %d: %v", offset, err)
		}
	}
}
