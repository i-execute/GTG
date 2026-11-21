package tl

import (
	"bytes"
	"errors"
	"testing"
)

func TestDecodeZeroCopyBorrowing(t *testing.T) {
	schema := testSchema(t)
	input := Dynamic{Name: "sample", Fields: map[string]any{
		"label":  "hello",
		"values": []any{int(3)},
		"node":   Dynamic{Name: "node", Fields: map[string]any{"value": int(41)}},
	}}
	encoded, err := schema.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	owned, unknown, err := schema.Decode(encoded)
	if err != nil || unknown != nil {
		t.Fatal(err)
	}
	borrowed, unknown, err := schema.DecodeZeroCopy(encoded)
	if err != nil || unknown != nil {
		t.Fatal(err)
	}
	ownedNode := owned.Fields["node"].(Dynamic)
	borrowedNode := borrowed.Fields["node"].(Dynamic)
	if ownedNode.Fields["value"] != borrowedNode.Fields["value"] {
		t.Fatal("decode mismatch")
	}
	unknownData := append([]byte{0xef, 0xbe, 0xad, 0xde}, encoded...)
	_, unknown, err = schema.DecodeZeroCopy(unknownData)
	if err != nil || unknown == nil || !unknown.Borrowed || !bytes.Equal(unknown.Data, unknownData) {
		t.Fatal("unknown borrowing mismatch")
	}
	clone := unknown.Clone()
	unknownData[4] ^= 1
	if clone.Borrowed || bytes.Equal(clone.Data, unknown.Data) {
		t.Fatal("unknown clone mismatch")
	}
}

func TestDecodeZeroCopyByteSliceAliasesInput(t *testing.T) {
	schema, err := Build([]Declaration{{Name: "blob", Constructor: 0x01020304, Result: "Blob", Fields: []Field{{Name: "data", Type: "bytes", Flag: -1}}}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := schema.Encode(Dynamic{Name: "blob", Fields: map[string]any{"data": []byte("borrowed")}})
	if err != nil {
		t.Fatal(err)
	}
	view, unknown, err := schema.DecodeZeroCopy(encoded)
	if err != nil || unknown != nil {
		t.Fatal(err)
	}
	copyValue, unknown, err := schema.Decode(encoded)
	if err != nil || unknown != nil {
		t.Fatal(err)
	}
	borrowed := view.Fields["data"].([]byte)
	owned := copyValue.Fields["data"].([]byte)
	encoded[5] = 'B'
	if string(borrowed) != "Borrowed" || string(owned) != "borrowed" {
		t.Fatal("borrowing contract mismatch")
	}
}

func TestDecodeLimits(t *testing.T) {
	schema := testSchema(t)
	input := Dynamic{Name: "sample", Fields: map[string]any{
		"label":  "0123456789",
		"values": []any{int(1), int(2)},
		"node":   Dynamic{Name: "node", Fields: map[string]any{"value": int(1)}},
	}}
	encoded, err := schema.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxInput = 4
	limits.MaxBytes = 4
	if _, _, err := schema.DecodeWithLimits(encoded, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("input limit: %v", err)
	}
	limits = DefaultLimits()
	limits.MaxBytes = 2
	if _, _, err := schema.DecodeWithLimits(encoded, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("bytes limit: %v", err)
	}
	limits = DefaultLimits()
	limits.MaxVector = 1
	if _, _, err := schema.DecodeWithLimits(encoded, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("vector limit: %v", err)
	}
}

func TestDecodeDepthLimit(t *testing.T) {
	schema, err := Build([]Declaration{
		{Name: "node", Constructor: 0x01020304, Result: "Node", Fields: []Field{{Name: "flags", Type: "#", Flag: -1}, {Name: "next", Type: "flags.0?Node", Flag: 0}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := Dynamic{Name: "node", Fields: map[string]any{"next": Dynamic{Name: "node", Fields: map[string]any{"next": Dynamic{Name: "node", Fields: map[string]any{"next": Dynamic{Name: "node", Fields: map[string]any{}}}}}}}}
	encoded, err := schema.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxDepth = 2
	if _, _, err := schema.DecodeZeroCopyWithLimits(encoded, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("depth limit: %v", err)
	}
}
