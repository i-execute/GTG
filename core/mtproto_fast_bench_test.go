package core

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func BenchmarkSHA256OneMiB(b *testing.B) {
	data := makePattern(1048576, 151)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = sha256.Sum256(data)
	}
}

func BenchmarkMTProtoInPlace(b *testing.B) {
	for _, size := range []int{64, 256, 1024, 4096, 65536, 1048576, 16777216} {
		b.Run(matrixSizeName(size), func(b *testing.B) {
			box, err := NewMTProto(makePattern(256, 152))
			if err != nil {
				b.Fatal(err)
			}
			packet := make([]byte, 24+size, 24+size+1024)
			copy(packet[24:], makePattern(size, 153))
			if _, err := box.SealInPlace(packet, ClientToServer); err != nil {
				b.Fatal(err)
			}
			b.Run("seal", func(b *testing.B) {
				work := packet[:24+size]
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if _, err := box.SealInPlace(work, ClientToServer); err != nil {
						b.Fatal(err)
					}
				}
			})
			sealed, err := box.SealInPlace(packet[:24+size], ClientToServer)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("open", func(b *testing.B) {
				work := append([]byte(nil), sealed...)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					copy(work, sealed)
					if _, err := box.OpenInPlace(work, ClientToServer); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkPaddingSources(b *testing.B) {
	for _, size := range []int{16, 256, 1024} {
		b.Run("crypto_rand/"+matrixSizeName(size), func(b *testing.B) {
			buf := make([]byte, size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := rand.Read(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("chacha8_buffered/"+matrixSizeName(size), func(b *testing.B) {
			var source paddingRNG
			buf := make([]byte, size)
			if err := source.bytes(buf); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := source.bytes(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
