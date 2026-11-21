package core

import (
	"hash/crc32"
	"testing"
)

func TestCRC32StandardVectors(t *testing.T) {
	input := []byte("123456789")
	if got := CRC32IEEE(input); got != 0xcbf43926 {
		t.Fatalf("IEEE CRC got %08x", got)
	}
	if got := CRC32Castagnoli(input); got != 0xe3069283 {
		t.Fatalf("Castagnoli CRC got %08x", got)
	}
	if CRC32IEEE(input) != crc32.ChecksumIEEE(input) {
		t.Fatal("IEEE standard path mismatch")
	}
}
