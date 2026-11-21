package core

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestCDNCTRAndHash(t *testing.T) {
	key := makePattern(32, 31)
	iv := makePattern(16, 32)
	plain := makePattern(8192, 33)
	ciphertext := make([]byte, len(plain))
	if err := CTRCDN(ciphertext, key, iv, plain, 0); err != nil {
		t.Fatal(err)
	}
	part := ciphertext[37:4117]
	hash := sha256.Sum256(part)
	expected := CDNFileHash{Offset: 37, Limit: len(part), Hash: hash}
	opened := make([]byte, len(part))
	if err := DecryptCDNPart(opened, key, iv, part, 37, expected); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain[37:4117]) {
		t.Fatal("random access CTR mismatch")
	}
	part[0] ^= 1
	if err := DecryptCDNPart(opened, key, iv, part, 37, expected); err == nil {
		t.Fatal("accepted altered CDN part")
	}
}

func TestCDNInputErrors(t *testing.T) {
	if err := CTRCDN(nil, make([]byte, 32), make([]byte, 16), nil, -1); err == nil {
		t.Fatal("accepted negative offset")
	}
	if err := CTRCDN(make([]byte, 1), make([]byte, 32), make([]byte, 16), []byte{1}, (int64(1)<<32)*16); err == nil {
		t.Fatal("accepted counter overflow")
	}
	if err := VerifyCDNPart(CDNFileHash{Offset: 0, Limit: 1}, nil); err == nil {
		t.Fatal("accepted hash length mismatch")
	}
}
