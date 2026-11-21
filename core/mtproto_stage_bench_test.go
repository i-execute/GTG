package core

import "testing"

func BenchmarkMTProtoStages(b *testing.B) {
	for _, size := range []int{64, 256, 1024, 4096, 16384, 65536, 524288, 1048576, 16777216} {
		b.Run(matrixSizeName(size), func(b *testing.B) {
			auth := makePattern(256, 33)
			box, err := NewMTProto(auth)
			if err != nil {
				b.Fatal(err)
			}
			plain := makePattern(size, 34)
			key := [16]byte{}
			box.messageKey(&key, plain, ClientToServer)
			b.Run("message_key", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					box.messageKey(&key, plain, ClientToServer)
				}
			})
			b.Run("derive", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					box.derive(&key, ClientToServer)
				}
			})
			b.Run("derive_transform", func(b *testing.B) {
				out := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					box.derive(&key, ClientToServer)
					if err := box.transform(out, plain, false); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("seal", func(b *testing.B) {
				out := make([]byte, 0, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if _, _, err := box.Seal(out[:0], plain, ClientToServer); err != nil {
						b.Fatal(err)
					}
				}
			})
			messageKey, ciphertext, err := box.Seal(make([]byte, 0, size), plain, ClientToServer)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("open", func(b *testing.B) {
				out := make([]byte, 0, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if _, err := box.Open(out[:0], messageKey[:], ciphertext, ClientToServer); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkMTProtoSHAPath(b *testing.B) {
	for _, native := range []bool{false, true} {
		name := "generic"
		if native {
			name = "sha_ni"
		}
		b.Run(name, func(b *testing.B) {
			sha256StateUseNative = native
			defer func() { sha256StateUseNative = true }()
			box, err := NewMTProto(makePattern(256, 154))
			if err != nil {
				b.Fatal(err)
			}
			plain := makePattern(1048576, 155)
			out := make([]byte, 0, len(plain))
			b.SetBytes(int64(len(plain)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := box.Seal(out[:0], plain, ClientToServer); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
