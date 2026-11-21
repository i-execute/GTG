package tl_test

import (
	"testing"

	"github.com/i-execute/GTG/internal/tlgen"
	"github.com/i-execute/GTG/tl"
)

func BenchmarkGeneratedCodec(b *testing.B) {
	schema := tlgen.Schema()
	input := tlgen.ConstructorError_C4B9F9BB{FCode1: 400, FText2: "FLOOD_WAIT_10"}.Dynamic()
	encoded, err := schema.Encode(input)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			value, err := schema.Encode(input)
			if err != nil {
				b.Fatal(err)
			}
			codecSink = value
		}
	})
	b.Run("decode_owned", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			value, unknown, err := schema.Decode(encoded)
			if err != nil || unknown != nil {
				b.Fatal(err)
			}
			codecDynamicSink = value
		}
	})
	b.Run("decode_borrowed", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			value, unknown, err := schema.DecodeZeroCopy(encoded)
			if err != nil || unknown != nil {
				b.Fatal(err)
			}
			codecDynamicSink = value
		}
	})
}

var codecSink []byte
var codecDynamicSink tl.Dynamic
