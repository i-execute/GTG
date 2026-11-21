package core

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
)

var ErrAuthKeySize = errors.New("gtg: MTProto authorization key must be 256 bytes")
var ErrMessageKeySize = errors.New("gtg: MTProto message key must be 16 bytes")
var ErrNonceSize = errors.New("gtg: invalid nonce length")
var ErrPBKDFIterations = errors.New("gtg: PBKDF2 iterations must be positive")

type Direction uint8

const (
	ClientToServer Direction = iota
	ServerToClient
)

func DeriveLocalKey(password string, salt []byte) ([32]byte, error) {
	return deriveLocalKeyNIExperiment([]byte(password), salt, 600000)
}

func TelegramPasswordHash(password string, salt1, salt2 []byte) ([32]byte, error) {
	var out [32]byte
	h1 := sum256(salt1, []byte(password), salt1)
	h2 := sum256(salt2, h1[:], salt2)
	h3, err := pbkdf2.Key(sha512.New, string(h2[:]), salt1, 100000, sha512.Size)
	if err != nil {
		return out, err
	}
	out = sum256(salt2, h3, salt2)
	clear(h1[:])
	clear(h2[:])
	clear(h3)
	return out, nil
}

func AuthorizationKeyID(authKey []byte) ([8]byte, error) {
	var out [8]byte
	if len(authKey) != 256 {
		return out, ErrAuthKeySize
	}
	sum := sha1.Sum(authKey)
	copy(out[:], sum[12:])
	clear(sum[:])
	return out, nil
}

func MessageKey(authKey, plaintext []byte, direction Direction) ([16]byte, error) {
	var out [16]byte
	if len(authKey) != 256 {
		return out, ErrAuthKeySize
	}
	if direction > ServerToClient {
		return out, errors.New("gtg: invalid MTProto direction")
	}
	x := int(direction) * 8
	sum := sum256(authKey[88+x:120+x], plaintext)
	copy(out[:], sum[8:24])
	clear(sum[:])
	return out, nil
}

func DeriveMessageAES(authKey, messageKey []byte, direction Direction) ([32]byte, [32]byte, error) {
	var key [32]byte
	var iv [32]byte
	if len(authKey) != 256 {
		return key, iv, ErrAuthKeySize
	}
	if len(messageKey) != 16 {
		return key, iv, ErrMessageKeySize
	}
	if direction > ServerToClient {
		return key, iv, errors.New("gtg: invalid MTProto direction")
	}
	x := int(direction) * 8
	a := sum256(messageKey, authKey[x:x+36])
	b := sum256(authKey[40+x:76+x], messageKey)
	copy(key[:8], a[:8])
	copy(key[8:24], b[8:24])
	copy(key[24:], a[24:])
	copy(iv[:8], b[:8])
	copy(iv[8:24], a[8:24])
	copy(iv[24:], b[24:])
	clear(a[:])
	clear(b[:])
	return key, iv, nil
}

func DeriveTemporaryAES(newNonce, serverNonce []byte) ([32]byte, [32]byte, error) {
	var key [32]byte
	var iv [32]byte
	if len(newNonce) != 32 || len(serverNonce) != 16 {
		return key, iv, ErrNonceSize
	}
	a := sum1(newNonce, serverNonce)
	b := sum1(serverNonce, newNonce)
	c := sum1(newNonce, newNonce)
	copy(key[:20], a[:])
	copy(key[20:], b[:12])
	copy(iv[:8], b[12:])
	copy(iv[8:28], c[:])
	copy(iv[28:], newNonce[:4])
	clear(a[:])
	clear(b[:])
	clear(c[:])
	return key, iv, nil
}

func NewNonceHash(newNonce, authKey []byte, number byte) ([16]byte, error) {
	var out [16]byte
	if len(newNonce) != 32 || len(authKey) != 256 {
		return out, ErrNonceSize
	}
	keyHash := sha1.Sum(authKey)
	sum := sum1(newNonce, []byte{number}, keyHash[:8])
	copy(out[:], sum[4:])
	clear(keyHash[:])
	clear(sum[:])
	return out, nil
}

func sum1(parts ...[]byte) [20]byte {
	h := sha1.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var out [20]byte
	h.Sum(out[:0])
	return out
}

func sum256(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}
