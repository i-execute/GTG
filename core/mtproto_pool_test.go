package core

import (
	"bytes"
	"testing"
)

func TestMTProtoPool(t *testing.T) {
	pool, err := NewMTProtoPool(2)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	streams := make([]MTProtoPacketStream, 4)
	plain := make([][]byte, len(streams))
	for i := range streams {
		box, err := NewMTProto(makePattern(256, byte(170+i)))
		if err != nil {
			t.Fatal(err)
		}
		plain[i] = makePattern(4096, byte(180+i))
		packet := make([]byte, 24+len(plain[i]), 24+len(plain[i])+1024)
		copy(packet[24:], plain[i])
		streams[i] = MTProtoPacketStream{Box: box, Packet: packet, Direction: ClientToServer}
	}
	if err := pool.Process(streams); err != nil {
		t.Fatal(err)
	}
	for i := range streams {
		streams[i].Open = true
	}
	if err := pool.Process(streams); err != nil {
		t.Fatal(err)
	}
	for i := range streams {
		if !bytes.Equal(streams[i].Payload[:len(plain[i])], plain[i]) {
			t.Fatalf("stream=%d", i)
		}
	}
}

func TestMTProtoPoolAllocs(t *testing.T) {
	pool, err := NewMTProtoPool(1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	box, err := NewMTProto(makePattern(256, 188))
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 24+4096, 24+4096+1024)
	streams := []MTProtoPacketStream{{Box: box, Packet: packet, Direction: ClientToServer}}
	if err := pool.Process(streams); err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		streams[0].Packet = packet[:24+4096]
		streams[0].Open = false
		if err := pool.Process(streams); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("allocs/op=%v", allocs)
	}
}
