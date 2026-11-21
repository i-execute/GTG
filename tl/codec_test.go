package tl

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func testSchema(t *testing.T) *Schema {
	t.Helper()
	schema, err := Build([]Declaration{
		{Name: "vector", Constructor: 0x1cb5c415, Result: "Vector t"},
		{Name: "node", Constructor: 0x10101010, Result: "Node", Fields: []Field{{Name: "value", Type: "int", Flag: -1}}},
		{Name: "sample", Constructor: 0x20202020, Result: "Sample", Fields: []Field{{Name: "flags", Type: "#", Flag: -1}, {Name: "enabled", Type: "flags.0?true", Flag: 0}, {Name: "label", Type: "flags.1?string", Flag: 1}, {Name: "values", Type: "Vector<int>", Flag: -1}, {Name: "node", Type: "Node", Flag: -1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func TestDynamicCodecRoundTrip(t *testing.T) {
	schema := testSchema(t)
	input := Dynamic{Name: "sample", Fields: map[string]any{
		"enabled": true,
		"label":   "hello",
		"values":  []any{int(3), int(-9)},
		"node":    Dynamic{Name: "node", Fields: map[string]any{"value": int(41)}},
	}}
	encoded, err := schema.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, unknown, err := schema.Decode(encoded)
	if err != nil || unknown != nil {
		t.Fatal(err)
	}
	if decoded.Name != "sample" || decoded.Fields["enabled"] != true || decoded.Fields["label"] != "hello" {
		t.Fatal("scalar mismatch")
	}
	values, ok := decoded.Fields["values"].([]any)
	if !ok || len(values) != 2 || values[0] != int32(3) || values[1] != int32(-9) {
		t.Fatal("vector mismatch")
	}
	node, ok := decoded.Fields["node"].(Dynamic)
	if !ok || node.Name != "node" || node.Fields["value"] != int32(41) {
		t.Fatal("object mismatch")
	}
	clear(encoded)
}

func TestUnknownConstructorIsPreserved(t *testing.T) {
	schema := testSchema(t)
	input := make([]byte, 8)
	binary.LittleEndian.PutUint32(input, 0xaabbccdd)
	binary.LittleEndian.PutUint32(input[4:], 7)
	_, unknown, err := schema.Decode(input)
	if err != nil || unknown == nil || unknown.Constructor != 0xaabbccdd || !bytes.Equal(unknown.Data, input) {
		t.Fatal(err)
	}
}

func FuzzDynamicDecode(f *testing.F) {
	schema, err := Build([]Declaration{{Name: "vector", Constructor: 0x1cb5c415, Result: "Vector t"}, {Name: "node", Constructor: 0x10101010, Result: "Node", Fields: []Field{{Name: "value", Type: "int", Flag: -1}}}})
	if err != nil {
		f.Fatal(err)
	}
	seed, err := schema.Encode(Dynamic{Name: "node", Fields: map[string]any{"value": int(1)}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = schema.Decode(input)
		_, _, _ = schema.DecodeZeroCopyWithLimits(input, DefaultLimits())
	})
}
