package core

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestIGEDecryptDifferential(t *testing.T) {
	if nativeIGEPrepare == nil {
		t.Skip("AES-NI unavailable")
	}
	for _, size := range []int{16, 32, 48, 64, 256, 4096, 65536} {
		key := makePattern(32, byte(size+7))
		iv := makePattern(32, byte(size+13))
		plain := makePattern(size, byte(size+19))
		ige, err := NewIGE(key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := make([]byte, size)
		if err := ige.Encrypt(ciphertext, plain, iv); err != nil {
			t.Fatal(err)
		}
		want := referenceIGEDecrypt(t, key, ciphertext, iv)
		baseline := make([]byte, size)
		decryptIGEAESNI(baseline, ciphertext, &ige.dec, (*[32]byte)(iv))
		if !bytes.Equal(baseline, want) {
			t.Fatalf("baseline mismatch size=%d", size)
		}
		inplace := append([]byte(nil), ciphertext...)
		decryptIGEAESNI(inplace, inplace, &ige.dec, (*[32]byte)(iv))
		if !bytes.Equal(inplace, want) {
			t.Fatalf("in-place mismatch size=%d", size)
		}
	}
}

func referenceIGEDecrypt(t *testing.T, key, src, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(src))
	var c [16]byte
	var p [16]byte
	copy(c[:], iv[:16])
	copy(p[:], iv[16:])
	for off := 0; off < len(src); off += aes.BlockSize {
		var input [16]byte
		copy(input[:], src[off:off+aes.BlockSize])
		xorBlock(&p, &input, &p)
		block.Decrypt(p[:], p[:])
		xorBlock(&p, &p, &c)
		copy(out[off:off+aes.BlockSize], p[:])
		c = input
	}
	return out
}
