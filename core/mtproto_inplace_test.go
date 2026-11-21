package core

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestMTProtoInPlace(t *testing.T) {
	box, err := NewMTProto(makePattern(256, 141))
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []Direction{ClientToServer, ServerToClient} {
		for _, size := range []int{0, 1, 64, 4096, 65536} {
			plain := makePattern(size, byte(size+11))
			packet := make([]byte, 24+len(plain), 24+len(plain)+1024)
			copy(packet[24:], plain)
			sealed, err := box.SealInPlace(packet, direction)
			if err != nil {
				t.Fatal(err)
			}
			if len(sealed) < 24+len(plain)+12 || len(sealed) > 24+len(plain)+1024 || len(sealed[24:])&15 != 0 {
				t.Fatalf("size=%d sealed=%d", size, len(sealed))
			}
			opened, err := box.OpenInPlace(sealed, direction)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened[:len(plain)], plain) {
				t.Fatalf("direction=%d size=%d", direction, size)
			}
		}
	}
}

func TestMTProtoInPlaceRejectsUniformly(t *testing.T) {
	box, err := NewMTProto(makePattern(256, 142))
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 24+64, 24+64+1024)
	copy(packet[24:], makePattern(64, 143))
	sealed, err := box.SealInPlace(packet, ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 8, len(sealed) - 1} {
		copy := append([]byte(nil), sealed...)
		copy[offset] ^= 1
		if _, err := box.OpenInPlace(copy, ClientToServer); !errors.Is(err, ErrMTProtoPacket) {
			t.Fatalf("offset=%d err=%v", offset, err)
		}
	}
}

func TestMTProtoInPlaceAllocsAfterSeed(t *testing.T) {
	box, err := NewMTProto(makePattern(256, 144))
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 24+4096, 24+4096+1024)
	if _, err := box.SealInPlace(packet, ClientToServer); err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		work := packet[:24+4096]
		if _, err := box.SealInPlace(work, ClientToServer); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("allocs/op=%v", allocs)
	}
}

func TestSHA256StateRandom(t *testing.T) {
	for _, size := range []int{0, 1, 55, 56, 63, 64, 65, 4096, 65537} {
		data := makePattern(size, byte(size+151))
		var state sha256State
		state.reset()
		for offset := 0; offset < len(data); {
			step := 1 + (offset*17+size)%97
			if step > len(data)-offset {
				step = len(data) - offset
			}
			state.write(data[offset : offset+step])
			offset += step
		}
		var got [32]byte
		state.sum(&got)
		want := sha256.Sum256(data)
		if got != want {
			t.Fatalf("size=%d", size)
		}
	}
}
