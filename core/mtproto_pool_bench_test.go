package core

import (
	"runtime"
	"testing"
)

func BenchmarkMTProtoPool(b *testing.B) {
	counts := []struct {
		name string
		n    int
	}{{"1", 1}, {"2", 2}, {"4", 4}, {"8", 8}, {"all", runtime.NumCPU()}}
	for _, size := range []int{4096, 65536, 524288} {
		for _, count := range counts {
			b.Run(matrixSizeName(size)+"/workers="+count.name, func(b *testing.B) {
				pool, err := NewMTProtoPool(count.n)
				if err != nil {
					b.Fatal(err)
				}
				defer pool.Close()
				streams := make([]MTProtoPacketStream, count.n)
				for i := range streams {
					box, err := NewMTProto(makePattern(256, byte(i+190)))
					if err != nil {
						b.Fatal(err)
					}
					packet := make([]byte, 24+size, 24+size+1024)
					copy(packet[24:], makePattern(size, byte(i+200)))
					streams[i] = MTProtoPacketStream{Box: box, Packet: packet, Direction: ClientToServer}
				}
				if err := pool.Process(streams); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(size * len(streams)))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					for i := range streams {
						streams[i].Packet = streams[i].Packet[:24+size]
						streams[i].Open = false
					}
					if err := pool.Process(streams); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
