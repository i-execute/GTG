package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

var ErrObfuscation = errors.New("gtg: obfuscation input rejected")

type ProxySecretKind uint8

const (
	ProxySecretPlain ProxySecretKind = iota
	ProxySecretDD
	ProxySecretEE
)

type Obfuscation struct {
	outbound cipher.Stream
	inbound  cipher.Stream
	outKey   [32]byte
	outIV    [16]byte
	inKey    [32]byte
	inIV     [16]byte
}

func ParseProxySecret(secret []byte) (ProxySecretKind, []byte, error) {
	if len(secret) == 16 {
		return ProxySecretPlain, secret, nil
	}
	if len(secret) == 17 && secret[0] == 0xdd {
		return ProxySecretDD, secret[1:], nil
	}
	if len(secret) >= 17 && secret[0] == 0xee {
		return ProxySecretEE, secret[1:17], nil
	}
	return ProxySecretPlain, nil, ErrObfuscation
}

func FakeTLSDomain(secret []byte) ([]byte, error) {
	if len(secret) < 17 || secret[0] != 0xee {
		return nil, ErrObfuscation
	}
	return secret[17:], nil
}

func NewObfuscatedInit(dcID int32, tag [4]byte, secret []byte) ([]byte, *Obfuscation, error) {
	for attempts := 0; attempts < 128; attempts++ {
		var init [64]byte
		if _, err := rand.Read(init[:]); err != nil {
			return nil, nil, ErrObfuscation
		}
		if forbiddenObfuscationPrefix(init[:]) {
			clear(init[:])
			continue
		}
		binary.LittleEndian.PutUint32(init[56:60], uint32(dcID))
		copy(init[60:], tag[:])
		box, err := newObfuscation(init[:], secret, false)
		if err != nil {
			clear(init[:])
			return nil, nil, err
		}
		var encrypted [64]byte
		box.outbound.XORKeyStream(encrypted[:], init[:])
		copy(init[56:], encrypted[56:])
		clear(encrypted[:])
		out := append([]byte(nil), init[:]...)
		clear(init[:])
		return out, box, nil
	}
	return nil, nil, ErrObfuscation
}

func NewObfuscationFromInit(init, secret []byte) (*Obfuscation, error) {
	if len(init) != 64 || forbiddenObfuscationPrefix(init) {
		return nil, ErrObfuscation
	}
	box, err := newObfuscation(init, secret, true)
	if err != nil {
		return nil, err
	}
	var discard [64]byte
	box.inbound.XORKeyStream(discard[:], discard[:])
	clear(discard[:])
	return box, nil
}

func (x *Obfuscation) Encrypt(dst, src []byte) error {
	if len(dst) < len(src) || x == nil || x.outbound == nil {
		return ErrObfuscation
	}
	x.outbound.XORKeyStream(dst[:len(src)], src)
	return nil
}

func (x *Obfuscation) Decrypt(dst, src []byte) error {
	if len(dst) < len(src) || x == nil || x.inbound == nil {
		return ErrObfuscation
	}
	x.inbound.XORKeyStream(dst[:len(src)], src)
	return nil
}

func (x *Obfuscation) Destroy() {
	clear(x.outKey[:])
	clear(x.outIV[:])
	clear(x.inKey[:])
	clear(x.inIV[:])
	x.outbound = nil
	x.inbound = nil
}

func FakeTLSClientDigest(secret, record []byte, randomOffset int, timestamp uint32) ([32]byte, error) {
	var out [32]byte
	kind, key, err := ParseProxySecret(secret)
	if err != nil || kind != ProxySecretEE || randomOffset < 0 || randomOffset+32 > len(record) {
		return out, ErrObfuscation
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(record[:randomOffset])
	var zeros [32]byte
	_, _ = mac.Write(zeros[:])
	_, _ = mac.Write(record[randomOffset+32:])
	copy(out[:], mac.Sum(nil))
	var stamp [4]byte
	binary.LittleEndian.PutUint32(stamp[:], timestamp)
	for i := range stamp {
		out[28+i] ^= stamp[i]
	}
	clear(stamp[:])
	return out, nil
}

func VerifyFakeTLSClientDigest(secret, record []byte, randomOffset int, timestamp uint32, digest []byte) error {
	if len(digest) != 32 {
		return ErrObfuscation
	}
	want, err := FakeTLSClientDigest(secret, record, randomOffset, timestamp)
	if err != nil {
		return err
	}
	valid := hmac.Equal(want[:], digest)
	clear(want[:])
	if !valid {
		return ErrObfuscation
	}
	return nil
}

func FakeTLSServerDigest(secret, clientDigest, response []byte, randomOffset int) ([32]byte, error) {
	var out [32]byte
	kind, key, err := ParseProxySecret(secret)
	if err != nil || kind != ProxySecretEE || len(clientDigest) != 32 || randomOffset < 0 || randomOffset+32 > len(response) {
		return out, ErrObfuscation
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(clientDigest)
	_, _ = mac.Write(response[:randomOffset])
	var zeros [32]byte
	_, _ = mac.Write(zeros[:])
	_, _ = mac.Write(response[randomOffset+32:])
	copy(out[:], mac.Sum(nil))
	return out, nil
}

func VerifyFakeTLSServerDigest(secret, clientDigest, response []byte, randomOffset int, digest []byte) error {
	if len(digest) != 32 {
		return ErrObfuscation
	}
	want, err := FakeTLSServerDigest(secret, clientDigest, response, randomOffset)
	if err != nil {
		return err
	}
	valid := hmac.Equal(want[:], digest)
	clear(want[:])
	if !valid {
		return ErrObfuscation
	}
	return nil
}

func newObfuscation(init, secret []byte, reverse bool) (*Obfuscation, error) {
	if len(init) != 64 {
		return nil, ErrObfuscation
	}
	_, key, err := ParseProxySecret(secret)
	if err != nil {
		return nil, err
	}
	var forward [48]byte
	copy(forward[:], init[8:56])
	var backward [48]byte
	for i := range backward {
		backward[i] = forward[len(backward)-1-i]
	}
	box := &Obfuscation{}
	if reverse {
		deriveObfuscation(&box.inKey, &box.inIV, forward[:32], forward[32:], key)
		deriveObfuscation(&box.outKey, &box.outIV, backward[:32], backward[32:], key)
	} else {
		deriveObfuscation(&box.outKey, &box.outIV, forward[:32], forward[32:], key)
		deriveObfuscation(&box.inKey, &box.inIV, backward[:32], backward[32:], key)
	}
	outBlock, err := aes.NewCipher(box.outKey[:])
	if err != nil {
		box.Destroy()
		return nil, ErrObfuscation
	}
	inBlock, err := aes.NewCipher(box.inKey[:])
	if err != nil {
		box.Destroy()
		return nil, ErrObfuscation
	}
	box.outbound = cipher.NewCTR(outBlock, box.outIV[:])
	box.inbound = cipher.NewCTR(inBlock, box.inIV[:])
	clear(forward[:])
	clear(backward[:])
	return box, nil
}

func deriveObfuscation(key *[32]byte, iv *[16]byte, baseKey, baseIV, secret []byte) {
	if len(secret) == 0 {
		copy(key[:], baseKey)
		copy(iv[:], baseIV)
		return
	}
	h := sha256.New()
	_, _ = h.Write(baseKey)
	_, _ = h.Write(secret)
	var keyHash [32]byte
	h.Sum(keyHash[:0])
	h.Reset()
	_, _ = h.Write(baseIV)
	_, _ = h.Write(secret)
	var ivHash [32]byte
	h.Sum(ivHash[:0])
	copy(key[:], keyHash[:])
	copy(iv[:], ivHash[:16])
	clear(keyHash[:])
	clear(ivHash[:])
}

func forbiddenObfuscationPrefix(init []byte) bool {
	if len(init) < 8 || init[0] == 0xef {
		return true
	}
	prefix := binary.LittleEndian.Uint32(init[:4])
	switch prefix {
	case 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xeeeeeeee:
		return true
	}
	return binary.LittleEndian.Uint32(init[4:8]) == 0
}
