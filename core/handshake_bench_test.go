package core

import "testing"

func BenchmarkFactorPQ(b *testing.B) {
	for _, value := range []uint64{1000003 * 1000033, 1000000007 * 1000000009, 2147483629 * 2147483647} {
		b.Run(uint64BenchmarkName(value), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := FactorPQ(value); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func uint64BenchmarkName(value uint64) string {
	var out [20]byte
	i := len(out)
	for {
		i--
		out[i] = byte(value%10) + '0'
		value /= 10
		if value == 0 {
			return string(out[i:])
		}
	}
}
