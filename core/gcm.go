package core

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var ErrGCMKeySize = errors.New("gtg: AES-GCM key must be 32 bytes")
var ErrGCMNonceSize = errors.New("gtg: AES-GCM nonce must be 12 bytes")
var ErrGCMDestination = errors.New("gtg: AES-GCM destination capacity is too short")

type GCM struct {
	aead cipher.AEAD
}

func NewGCM(key []byte) (*GCM, error) {
	if len(key) != 32 {
		return nil, ErrGCMKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, err
	}
	return &GCM{aead: aead}, nil
}

func (x *GCM) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, ErrGCMNonceSize
	}
	if cap(dst)-len(dst) < len(plaintext)+x.aead.Overhead() {
		return nil, ErrGCMDestination
	}
	return x.aead.Seal(dst, nonce, plaintext, additionalData), nil
}

func (x *GCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, ErrGCMNonceSize
	}
	if len(ciphertext) < x.aead.Overhead() || cap(dst)-len(dst) < len(ciphertext)-x.aead.Overhead() {
		return nil, ErrGCMDestination
	}
	plaintext, err := x.aead.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		clear(dst)
		return nil, err
	}
	return plaintext, nil
}
