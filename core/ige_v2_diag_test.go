package core

import (
	"runtime"
	"sync"
	"testing"
)

var igeV2DiagSink []byte

func igeV2DiagSizeName(size int) string {
	switch size {
	case 4096:
		return "4KiB"
	case 16384:
		return "16KiB"
	case 65536:
		return "64KiB"
	case 262144:
		return "256KiB"
	case 524288:
		return "512KiB"
	case 1048576:
		return "1MiB"
	default:
		return "size"
	}
}

func BenchmarkIGEV2Allocation(b *testing.B) {
	for _, size := range []int{4096, 16384, 65536, 262144, 524288, 1048576} {
		b.Run(igeV2DiagSizeName(size), func(b *testing.B) {
			key := makePattern(32, 151)
			iv := makePattern(32, 152)
			ige, err := NewIGE(key)
			if err != nil {
				b.Fatal(err)
			}
			plain := makePattern(size, 153)
			ciphertext := make([]byte, size)
			if err := ige.Encrypt(ciphertext, plain, iv); err != nil {
				b.Fatal(err)
			}
			b.Run("allocate", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					igeV2DiagSink = make([]byte, size)
				}
			})
			b.Run("allocate_clear", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					igeV2DiagSink = make([]byte, size)
					clear(igeV2DiagSink)
				}
			})
			b.Run("decrypt_caller", func(b *testing.B) {
				dst := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if err := ige.Decrypt(dst, ciphertext, iv); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("decrypt_allocate", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					dst := make([]byte, size)
					if err := ige.Decrypt(dst, ciphertext, iv); err != nil {
						b.Fatal(err)
					}
					igeV2DiagSink = dst
				}
			})
			b.Run("encrypt_caller", func(b *testing.B) {
				dst := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if err := ige.Encrypt(dst, plain, iv); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("encrypt_allocate", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					dst := make([]byte, size)
					if err := ige.Encrypt(dst, plain, iv); err != nil {
						b.Fatal(err)
					}
					igeV2DiagSink = dst
				}
			})
			b.Run("pool_get_without_release", func(b *testing.B) {
				pool := sync.Pool{New: func() any { return make([]byte, size) }}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					dst := pool.Get().([]byte)
					if err := ige.Decrypt(dst, ciphertext, iv); err != nil {
						b.Fatal(err)
					}
					igeV2DiagSink = dst
				}
			})
			b.Run("pool_get_release", func(b *testing.B) {
				pool := sync.Pool{New: func() any { return make([]byte, size) }}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					dst := pool.Get().([]byte)
					if err := ige.Decrypt(dst, ciphertext, iv); err != nil {
						b.Fatal(err)
					}
					pool.Put(dst)
				}
			})
		})
	}
}

func BenchmarkIGEV2GCTouch(b *testing.B) {
	for _, size := range []int{4096, 65536, 524288, 1048576} {
		b.Run(sizeName(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				buffer := make([]byte, size)
				runtime.KeepAlive(buffer)
			}
		})
	}
}
