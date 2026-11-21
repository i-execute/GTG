package core

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestFactorPQ(t *testing.T) {
	for _, item := range []struct {
		p uint64
		q uint64
	}{{3, 5}, {1000003, 1000033}, {1000000007, 1000000009}, {2147483629, 2147483647}} {
		p, q, err := FactorPQ(item.p * item.q)
		if err != nil {
			t.Fatal(err)
		}
		if p != item.p || q != item.q {
			t.Fatalf("got %d %d want %d %d", p, q, item.p, item.q)
		}
	}
	if _, _, err := FactorPQ(17); err == nil {
		t.Fatal("accepted prime")
	}
}

func TestTemporaryAESAndDHAnswer(t *testing.T) {
	newNonce := makePattern(32, 211)
	serverNonce := makePattern(16, 212)
	material, err := DeriveHandshakeTemporaryAES(newNonce, serverNonce)
	if err != nil {
		t.Fatal(err)
	}
	inner := makePattern(79, 213)
	ciphertext, err := EncryptDHAnswer(inner, material, bytes.NewReader(makePattern(64, 214)))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := DecryptDHAnswer(ciphertext, material, len(inner))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, inner) {
		t.Fatal("DH answer mismatch")
	}
	salt, err := ServerSalt(newNonce, serverNonce)
	if err != nil {
		t.Fatal(err)
	}
	if salt == [8]byte{} {
		t.Fatal("zero salt")
	}
}

func TestRSAEncryptPad(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	modulus := make([]byte, 256)
	private.N.FillBytes(modulus)
	exponent := uint64Bytes(uint64(private.E))
	data := makePattern(120, 215)
	sealed, err := RSAEncryptPad(data, RSAPublicKey{Modulus: modulus, Exponent: exponent}, bytes.NewReader(makePattern(512, 216)))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := new(big.Int).SetBytes(sealed)
	plain := new(big.Int).Exp(ciphertext, private.D, private.N)
	var encoded [256]byte
	plain.FillBytes(encoded[:])
	mask := sha256.Sum256(encoded[32:])
	for i := 0; i < 32; i++ {
		encoded[i] ^= mask[i]
	}
	ige, err := NewIGE(encoded[:32])
	if err != nil {
		t.Fatal(err)
	}
	var cleartext [224]byte
	var iv [32]byte
	if err := ige.Decrypt(cleartext[:], encoded[32:], iv[:]); err != nil {
		t.Fatal(err)
	}
	ige.Destroy()
	var padded [192]byte
	for i := range padded {
		padded[i] = cleartext[191-i]
	}
	hash := sha256.Sum256(append(encoded[:32:32], padded[:]...))
	if !bytes.Equal(cleartext[192:], hash[:]) || !bytes.Equal(padded[:len(data)], data) {
		t.Fatal("RSA_PAD mismatch")
	}
	ciphertext.SetInt64(0)
	plain.SetInt64(0)
	clear(modulus)
	clear(exponent)
	clear(data)
	clear(sealed)
	clear(encoded[:])
	clear(mask[:])
	clear(cleartext[:])
	clear(padded[:])
	clear(hash[:])
}
