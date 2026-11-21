package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var ErrCDN = errors.New("gtg: CDN input rejected")

type CDNFileHash struct {
	Offset int64
	Limit  int
	Hash   [32]byte
}

type CDN struct {
	key   [32]byte
	iv    [aes.BlockSize]byte
	block cipher.Block
}

type CDNStream struct {
	stream    cipher.Stream
	remaining uint64
}

func NewCDN(key, iv []byte) (*CDN, error) {
	if len(key) != 32 || len(iv) != aes.BlockSize {
		return nil, ErrCDN
	}
	x := &CDN{}
	copy(x.key[:], key)
	copy(x.iv[:], iv)
	block, err := aes.NewCipher(x.key[:])
	if err != nil {
		x.Destroy()
		return nil, ErrCDN
	}
	x.block = block
	return x, nil
}

func VerifyCDNPart(expected CDNFileHash, ciphertext []byte) error {
	if expected.Offset < 0 || expected.Limit < 0 || expected.Limit != len(ciphertext) {
		return ErrCDN
	}
	digest := sha256.Sum256(ciphertext)
	valid := subtle.ConstantTimeCompare(digest[:], expected.Hash[:])
	clear(digest[:])
	if valid != 1 {
		return ErrCDN
	}
	return nil
}

func (x *CDN) VerifyAndDecrypt(dst, ciphertext []byte, offset int64, expected CDNFileHash) error {
	if err := VerifyCDNPart(expected, ciphertext); err != nil || expected.Offset != offset {
		return ErrCDN
	}
	stream, err := x.Open(offset)
	if err != nil {
		return err
	}
	return stream.Crypt(dst, ciphertext)
}

func (x *CDN) Open(offset int64) (*CDNStream, error) {
	if x == nil || x.block == nil || !validCDNRange(offset, 0) {
		return nil, ErrCDN
	}
	var counter [aes.BlockSize]byte
	copy(counter[:], x.iv[:])
	blockIndex := uint64(offset) / aes.BlockSize
	binary.BigEndian.PutUint32(counter[12:], uint32(blockIndex))
	stream := &CDNStream{stream: cipher.NewCTR(x.block, counter[:]), remaining: (uint64(1) << 36) - uint64(offset)}
	withinBlock := int(uint64(offset) % aes.BlockSize)
	if withinBlock != 0 {
		var discarded [aes.BlockSize]byte
		stream.stream.XORKeyStream(discarded[:withinBlock], discarded[:withinBlock])
		clear(discarded[:])
	}
	clear(counter[:])
	return stream, nil
}

func (x *CDNStream) Crypt(dst, input []byte) error {
	if x == nil || x.stream == nil || len(dst) < len(input) || uint64(len(input)) > x.remaining {
		return ErrCDN
	}
	x.stream.XORKeyStream(dst[:len(input)], input)
	x.remaining -= uint64(len(input))
	return nil
}

func (x *CDNStream) Destroy() {
	if x != nil {
		x.stream = nil
		x.remaining = 0
	}
}

func (x *CDN) Destroy() {
	if x == nil {
		return
	}
	clear(x.key[:])
	clear(x.iv[:])
	x.block = nil
}

func DecryptCDNPart(dst, key, iv, ciphertext []byte, offset int64, expected CDNFileHash) error {
	x, err := NewCDN(key, iv)
	if err != nil {
		return ErrCDN
	}
	defer x.Destroy()
	return x.VerifyAndDecrypt(dst, ciphertext, offset, expected)
}

func CTRCDN(dst, key, iv, input []byte, offset int64) error {
	x, err := NewCDN(key, iv)
	if err != nil {
		return ErrCDN
	}
	defer x.Destroy()
	stream, err := x.Open(offset)
	if err != nil {
		return err
	}
	defer stream.Destroy()
	return stream.Crypt(dst, input)
}

func validCDNRange(offset int64, length int) bool {
	if offset < 0 || length < 0 {
		return false
	}
	const span uint64 = uint64(1) << 36
	start := uint64(offset)
	return start <= span && uint64(length) <= span-start
}
