package tl

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

func TestDynamicCodecProperty(t *testing.T) {
	schema := testSchema(t)
	random := rand.New(rand.NewPCG(17, 23))
	for index := 0; index < 500; index++ {
		label := make([]byte, random.IntN(80))
		for position := range label {
			label[position] = byte(32 + random.IntN(90))
		}
		input := Dynamic{Name: "sample", Fields: map[string]any{
			"enabled": index&1 == 0,
			"values":  []any{random.IntN(1 << 20), -random.IntN(1 << 20)},
			"node":    Dynamic{Name: "node", Fields: map[string]any{"value": random.IntN(1 << 20)}},
		}}
		if index&1 != 0 {
			input.Fields["label"] = string(label)
		}
		encoded, err := schema.Encode(input)
		if err != nil {
			t.Fatal(err)
		}
		decoded, unknown, err := schema.Decode(encoded)
		if err != nil || unknown != nil || decoded.Name != input.Name {
			t.Fatal(err)
		}
		encodedAgain, err := schema.Encode(decoded)
		if err != nil || !bytes.Equal(encoded, encodedAgain) {
			t.Fatal(err)
		}
	}
}

func TestDynamicCodecIndependentPrimitiveBytes(t *testing.T) {
	schema := testSchema(t)
	encoded, err := schema.Encode(Dynamic{Name: "node", Fields: map[string]any{"value": int(-7)}})
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 8)
	binary.LittleEndian.PutUint32(want[:4], 0x10101010)
	value := int32(-7)
	binary.LittleEndian.PutUint32(want[4:], uint32(value))
	if !bytes.Equal(encoded, want) {
		t.Fatalf("got %x want %x", encoded, want)
	}
}
