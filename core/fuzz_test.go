package core

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func FuzzIGE(f *testing.F) {
	f.Add([]byte("key"), []byte("iv"), []byte("payload"))
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 65536))
	f.Fuzz(func(t *testing.T, keySeed, ivSeed, payload []byte) {
		if len(payload) > 65536 {
			payload = payload[:65536]
		}
		payload = payload[:len(payload)&^15]
		key := sha256.Sum256(keySeed)
		iv := sha256.Sum256(ivSeed)
		ige, err := NewIGE(key[:])
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := make([]byte, len(payload))
		if err := ige.Encrypt(ciphertext, payload, iv[:]); err != nil {
			t.Fatal(err)
		}
		plain := make([]byte, len(payload))
		if err := ige.Decrypt(plain, ciphertext, iv[:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, payload) {
			t.Fatal("round-trip mismatch")
		}
	})
}

func FuzzGCM(f *testing.F) {
	f.Add([]byte("key"), []byte("nonce"), []byte("aad"), []byte("payload"))
	f.Fuzz(func(t *testing.T, keySeed, nonceSeed, aad, payload []byte) {
		if len(aad) > 4096 {
			aad = aad[:4096]
		}
		if len(payload) > 65536 {
			payload = payload[:65536]
		}
		key := sha256.Sum256(keySeed)
		nonceHash := sha256.Sum256(nonceSeed)
		gcm, err := NewGCM(key[:])
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := gcm.Seal(make([]byte, 0, len(payload)+16), nonceHash[:12], payload, aad)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := gcm.Open(make([]byte, 0, len(payload)), nonceHash[:12], ciphertext, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, payload) {
			t.Fatal("round-trip mismatch")
		}
	})
}
