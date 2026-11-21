package bootstrap

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"github.com/i-execute/GTG/core"
)

var ErrLegacy = errors.New("gtg: legacy MTProto packet rejected")

type legacyMTProto struct {
	auth   [256]byte
	authID [8]byte
}

func newLegacyMTProto(auth []byte) (*legacyMTProto, error) {
	if len(auth) != 256 {
		return nil, ErrLegacy
	}
	result := &legacyMTProto{}
	copy(result.auth[:], auth)
	id, err := core.AuthorizationKeyID(auth)
	if err != nil {
		result.destroy()
		return nil, ErrLegacy
	}
	result.authID = id
	return result, nil
}

func (x *legacyMTProto) destroy() {
	if x == nil {
		return
	}
	clear(x.auth[:])
	clear(x.authID[:])
}

func (x *legacyMTProto) seal(payload []byte, toServer bool) ([]byte, error) {
	if x == nil || len(payload) < 32 || len(payload) > 1<<20 {
		return nil, ErrLegacy
	}
	padding := (16 - len(payload)&15) & 15
	plain := make([]byte, len(payload)+padding)
	copy(plain, payload)
	if padding != 0 {
		if _, err := io.ReadFull(rand.Reader, plain[len(payload):]); err != nil {
			clear(plain)
			return nil, ErrLegacy
		}
	}
	hash := sha1.Sum(payload)
	key, iv := x.derive(hash[4:20], toServer)
	ige, err := core.NewIGE(key[:])
	clear(key[:])
	if err != nil {
		clear(iv[:])
		clear(plain)
		clear(hash[:])
		return nil, ErrLegacy
	}
	packet := make([]byte, 24+len(plain))
	copy(packet[:8], x.authID[:])
	copy(packet[8:24], hash[4:20])
	err = ige.Encrypt(packet[24:], plain, iv[:])
	ige.Destroy()
	clear(iv[:])
	clear(plain)
	clear(hash[:])
	if err != nil {
		clear(packet)
		return nil, ErrLegacy
	}
	return packet, nil
}

func (x *legacyMTProto) open(packet []byte, fromServer bool) ([]byte, error) {
	if x == nil || len(packet) < 40 || len(packet[24:])&15 != 0 || subtle.ConstantTimeCompare(packet[:8], x.authID[:]) != 1 {
		return nil, ErrLegacy
	}
	key, iv := x.derive(packet[8:24], !fromServer)
	ige, err := core.NewIGE(key[:])
	clear(key[:])
	if err != nil {
		clear(iv[:])
		return nil, ErrLegacy
	}
	plain := make([]byte, len(packet)-24)
	err = ige.Decrypt(plain, packet[24:], iv[:])
	ige.Destroy()
	clear(iv[:])
	if err != nil {
		clear(plain)
		return nil, ErrLegacy
	}
	if len(plain) < 32 {
		clear(plain)
		return nil, ErrLegacy
	}
	length := int(binary.LittleEndian.Uint32(plain[28:32]))
	if length < 4 || length&3 != 0 || length > len(plain)-32 {
		clear(plain)
		return nil, ErrLegacy
	}
	hash := sha1.Sum(plain[:32+length])
	valid := subtle.ConstantTimeCompare(hash[4:20], packet[8:24])
	clear(hash[:])
	if valid != 1 {
		clear(plain)
		return nil, ErrLegacy
	}
	return plain, nil
}

func (x *legacyMTProto) derive(messageKey []byte, toServer bool) ([32]byte, [32]byte) {
	var key [32]byte
	var iv [32]byte
	offset := 8
	if toServer {
		offset = 0
	}
	a := sha1.Sum(append(append([]byte(nil), messageKey...), x.auth[offset:offset+32]...))
	b := sha1.Sum(append(append(append([]byte(nil), x.auth[32+offset:48+offset]...), messageKey...), x.auth[48+offset:64+offset]...))
	c := sha1.Sum(append(append([]byte(nil), x.auth[64+offset:96+offset]...), messageKey...))
	d := sha1.Sum(append(append([]byte(nil), messageKey...), x.auth[96+offset:128+offset]...))
	copy(key[:8], a[:8])
	copy(key[8:20], b[8:20])
	copy(key[20:], c[4:16])
	copy(iv[:12], a[8:20])
	copy(iv[12:20], b[:8])
	copy(iv[20:24], c[16:20])
	copy(iv[24:], d[:8])
	clear(a[:])
	clear(b[:])
	clear(c[:])
	clear(d[:])
	return key, iv
}
