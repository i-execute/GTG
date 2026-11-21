package core

import (
	"crypto/sha256"
	"strconv"
	"testing"
)

func BenchmarkCDNCTR(b *testing.B) {
	for _, size := range []int{64, 256, 1024, 4096, 16384, 65536, 524288, 1048576, 16777216} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			key := makePattern(32, 41)
			iv := makePattern(16, 42)
			cdn, err := NewCDN(key, iv)
			if err != nil {
				b.Fatal(err)
			}
			defer cdn.Destroy()
			stream, err := cdn.Open(0)
			if err != nil {
				b.Fatal(err)
			}
			defer stream.Destroy()
			src := makePattern(size, 43)
			dst := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := stream.Crypt(dst, src); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCRC32(b *testing.B) {
	data := makePattern(1048576, 44)
	for _, item := range []struct {
		name string
		fn   func([]byte) uint32
	}{{"IEEE", CRC32IEEE}, {"Castagnoli", CRC32Castagnoli}} {
		b.Run(item.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			var sum uint32
			for b.Loop() {
				sum = item.fn(data)
			}
			if sum == 0 {
				b.Fatal(sum)
			}
		})
	}
}

func BenchmarkVerifyCDNPart(b *testing.B) {
	data := makePattern(1048576, 45)
	hash := sha256.Sum256(data)
	expected := CDNFileHash{Offset: 0, Limit: len(data), Hash: hash}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := VerifyCDNPart(expected, data); err != nil {
			b.Fatal(err)
		}
	}
}
