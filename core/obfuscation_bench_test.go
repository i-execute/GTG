package core

import (
	"strconv"
	"testing"
)

func BenchmarkObfuscationCTR(b *testing.B) {
	for _, size := range []int{64, 256, 1024, 4096, 16384, 65536, 524288, 1048576, 16777216} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			secret := makePattern(16, 241)
			init, box, err := NewObfuscatedInit(2, [4]byte{0xee, 0xee, 0xee, 0xee}, secret)
			if err != nil {
				b.Fatal(err)
			}
			defer box.Destroy()
			clear(init)
			src := makePattern(size, 242)
			dst := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := box.Encrypt(dst, src); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFakeTLSHMAC(b *testing.B) {
	secret := append([]byte{0xee}, makePattern(16, 243)...)
	secret = append(secret, []byte("example.com")...)
	record := makePattern(517, 244)
	b.ReportAllocs()
	b.SetBytes(int64(len(record)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := FakeTLSClientDigest(secret, record, 11, 1700000000); err != nil {
			b.Fatal(err)
		}
	}
}
