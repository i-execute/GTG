package client

import (
	"testing"

	"github.com/i-execute/GTG/internal/tlgen"
)

func BenchmarkRPCResultDecode(b *testing.B) {
	schema := tlgen.Schema()
	encoded, err := schema.Encode(tlgen.ConstructorError_C4B9F9BB{FCode1: 420, FText2: "FLOOD_WAIT_10"}.Dynamic())
	if err != nil {
		b.Fatal(err)
	}
	instance := &Client{schema: schema}
	b.ReportAllocs()
	for b.Loop() {
		value, matched, err := instance.decodeResult(encoded)
		if err != nil || !matched || value.Name != "error" {
			b.Fatal("ordinary result decode mismatch")
		}
	}
}
