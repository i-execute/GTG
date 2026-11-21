package telegram

import "testing"

func TestPublicSchemaBorrowedBytes(t *testing.T) {
	input := ConstructorIpPortSecret_37982646{FIpv41: 1, FPort2: 443, FSecret3: []byte("secret")}
	encoded, err := Schema().Encode(input.Dynamic())
	if err != nil {
		t.Fatal(err)
	}
	value, unknown, err := Schema().DecodeZeroCopy(encoded)
	if err != nil || unknown != nil {
		t.Fatal(err)
	}
	decoded, ok := ConstructorIpPortSecret_37982646FromDynamic(value)
	if !ok {
		t.Fatal("typed borrowed decode mismatch")
	}
	encoded[13] = 'S'
	if string(decoded.FSecret3) != "Secret" {
		t.Fatal("borrowed bytes did not alias input")
	}
}
