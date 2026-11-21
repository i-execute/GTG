package telegram

import "testing"

func TestPublicTypedSurfaceRoundTrip(t *testing.T) {
	input := ConstructorError_C4B9F9BB{FCode1: 400, FText2: "BAD_REQUEST"}
	encoded, err := Schema().Encode(input.Dynamic())
	if err != nil {
		t.Fatal(err)
	}
	value, unknown, err := Schema().Decode(encoded)
	if err != nil || unknown != nil {
		t.Fatal(err)
	}
	decoded, ok := ConstructorError_C4B9F9BBFromDynamic(value)
	if !ok || decoded.FCode1 != 400 || decoded.FText2 != "BAD_REQUEST" {
		t.Fatal("public typed round trip mismatch")
	}
	if Layer != 233 || SchemaSHA256 == "" || SchemaRevision == "" {
		t.Fatal("public schema metadata mismatch")
	}
}
