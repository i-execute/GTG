package core

import (
	"crypto/aes"
	"crypto/subtle"
	"errors"
)

var ErrMTProtoPadding = errors.New("gtg: MTProto plaintext must be AES block aligned")
var ErrMTProtoDestination = errors.New("gtg: MTProto destination capacity is too short")
var ErrMTProtoMessageKey = errors.New("gtg: MTProto message key mismatch")
var ErrMTProtoPacket = errors.New("gtg: MTProto packet rejected")

type MTProto struct {
	auth     [256]byte
	authID   [8]byte
	hash     sha256State
	key      [32]byte
	iv       [32]byte
	expected [16]byte
	actual   [16]byte
	engine   IGE
	padding  paddingRNG
}

type MTProtoSealStream struct {
	Box        *MTProto
	Dst        []byte
	Plaintext  []byte
	Direction  Direction
	MessageKey [16]byte
	Ciphertext []byte
}

type MTProtoOpenStream struct {
	Box        *MTProto
	Dst        []byte
	Ciphertext []byte
	MessageKey []byte
	Direction  Direction
	Plaintext  []byte
}

func NewMTProto(authKey []byte) (*MTProto, error) {
	if len(authKey) != 256 {
		return nil, ErrAuthKeySize
	}
	x := &MTProto{}
	copy(x.auth[:], authKey)
	id, err := AuthorizationKeyID(authKey)
	if err != nil {
		clear(x.auth[:])
		return nil, err
	}
	x.authID = id
	x.hash.reset()
	return x, nil
}

func (x *MTProto) Destroy() {
	clear(x.auth[:])
	clear(x.authID[:])
	clear(x.key[:])
	clear(x.iv[:])
	clear(x.expected[:])
	clear(x.actual[:])
	clear(x.engine.key[:])
	clear(x.engine.enc[:])
	clear(x.engine.dec[:])
	x.engine.block = nil
	x.padding.clear()
	x.hash.reset()
}

func (x *MTProto) Seal(dst, plaintext []byte, direction Direction) ([16]byte, []byte, error) {
	if len(plaintext)&15 != 0 {
		return [16]byte{}, nil, ErrMTProtoPadding
	}
	if cap(dst)-len(dst) < len(plaintext) {
		return [16]byte{}, nil, ErrMTProtoDestination
	}
	if direction > ServerToClient {
		return [16]byte{}, nil, errors.New("gtg: invalid MTProto direction")
	}
	x.messageKey(&x.expected, plaintext, direction)
	x.derive(&x.expected, direction)
	out := dst[:len(dst)+len(plaintext)]
	err := x.transform(out[len(dst):], plaintext, false)
	if err != nil {
		clear(out[len(dst):])
		clear(x.expected[:])
		return [16]byte{}, nil, err
	}
	messageKey := x.expected
	clear(x.expected[:])
	return messageKey, out, nil
}

func (x *MTProto) Open(dst, messageKey, ciphertext []byte, direction Direction) ([]byte, error) {
	if len(messageKey) != 16 {
		return nil, ErrMessageKeySize
	}
	if len(ciphertext)&15 != 0 {
		return nil, ErrMTProtoPadding
	}
	if cap(dst)-len(dst) < len(ciphertext) {
		return nil, ErrMTProtoDestination
	}
	if direction > ServerToClient {
		return nil, errors.New("gtg: invalid MTProto direction")
	}
	copy(x.expected[:], messageKey)
	x.derive(&x.expected, direction)
	out := dst[:len(dst)+len(ciphertext)]
	err := x.transform(out[len(dst):], ciphertext, true)
	if err != nil {
		clear(out[len(dst):])
		return nil, err
	}
	x.messageKey(&x.actual, out[len(dst):], direction)
	valid := subtle.ConstantTimeCompare(x.actual[:], x.expected[:]) == 1
	clear(x.actual[:])
	clear(x.expected[:])
	if !valid {
		clear(out[len(dst):])
		return nil, ErrMTProtoMessageKey
	}
	return out, nil
}

func (x *MTProto) SealInPlace(packet []byte, direction Direction) ([]byte, error) {
	if direction > ServerToClient || len(packet) < 24 {
		return nil, ErrMTProtoPacket
	}
	plaintextLength := len(packet) - 24
	minimum := 12 + ((16 - (plaintextLength+12)&15) & 15)
	count := (1024-minimum)/16 + 1
	random, err := x.padding.uint32()
	if err != nil {
		return nil, ErrMTProtoPacket
	}
	paddingLength := minimum + int(random%uint32(count))*16
	if cap(packet) < len(packet)+paddingLength {
		return nil, ErrMTProtoPacket
	}
	packet = packet[:len(packet)+paddingLength]
	payload := packet[24:]
	if err := x.padding.bytes(payload[plaintextLength:]); err != nil {
		clear(payload[plaintextLength:])
		return nil, ErrMTProtoPacket
	}
	x.messageKey(&x.expected, payload, direction)
	x.derive(&x.expected, direction)
	if err := x.transform(payload, payload, false); err != nil {
		clear(payload)
		clear(x.expected[:])
		return nil, ErrMTProtoPacket
	}
	copy(packet[:8], x.authID[:])
	copy(packet[8:24], x.expected[:])
	clear(x.expected[:])
	return packet, nil
}

func (x *MTProto) OpenInPlace(packet []byte, direction Direction) ([]byte, error) {
	if direction > ServerToClient || len(packet) < 40 || len(packet[24:])&15 != 0 {
		return nil, ErrMTProtoPacket
	}
	if subtle.ConstantTimeCompare(packet[:8], x.authID[:]) != 1 {
		return nil, ErrMTProtoPacket
	}
	payload := packet[24:]
	copy(x.expected[:], packet[8:24])
	x.derive(&x.expected, direction)
	if err := x.transform(payload, payload, true); err != nil {
		clear(payload)
		clear(x.expected[:])
		return nil, ErrMTProtoPacket
	}
	x.messageKey(&x.actual, payload, direction)
	valid := subtle.ConstantTimeCompare(x.actual[:], x.expected[:])
	clear(x.actual[:])
	clear(x.expected[:])
	if valid != 1 {
		clear(payload)
		return nil, ErrMTProtoPacket
	}
	return payload, nil
}

func (x *MTProto) AuthorizationKeyID() [8]byte {
	return x.authID
}

func (x *MTProto) SealBatch(streams []MTProtoSealStream) error {
	for i := range streams {
		stream := &streams[i]
		if stream.Box == nil {
			return ErrAuthKeySize
		}
		if len(stream.Plaintext)&15 != 0 {
			return ErrMTProtoPadding
		}
		if cap(stream.Dst)-len(stream.Dst) < len(stream.Plaintext) {
			return ErrMTProtoDestination
		}
		if stream.Direction > ServerToClient {
			return errors.New("gtg: invalid MTProto direction")
		}
	}
	for i := range streams {
		stream := &streams[i]
		messageKey, ciphertext, err := stream.Box.Seal(stream.Dst, stream.Plaintext, stream.Direction)
		if err != nil {
			return err
		}
		stream.MessageKey = messageKey
		stream.Ciphertext = ciphertext
	}
	return nil
}

func (x *MTProto) OpenBatch(streams []MTProtoOpenStream) error {
	for i := range streams {
		stream := &streams[i]
		if stream.Box == nil {
			return ErrAuthKeySize
		}
		if len(stream.MessageKey) != 16 {
			return ErrMessageKeySize
		}
		if len(stream.Ciphertext)&15 != 0 {
			return ErrMTProtoPadding
		}
		if cap(stream.Dst)-len(stream.Dst) < len(stream.Ciphertext) {
			return ErrMTProtoDestination
		}
		if stream.Direction > ServerToClient {
			return errors.New("gtg: invalid MTProto direction")
		}
	}
	for i := range streams {
		stream := &streams[i]
		plaintext, err := stream.Box.Open(stream.Dst, stream.MessageKey, stream.Ciphertext, stream.Direction)
		if err != nil {
			return err
		}
		stream.Plaintext = plaintext
	}
	return nil
}

func (x *MTProto) messageKey(out *[16]byte, plaintext []byte, direction Direction) {
	var full [32]byte
	offset := int(direction) * 8
	x.hash.reset()
	x.hash.write(x.auth[88+offset : 120+offset])
	x.hash.write(plaintext)
	x.hash.sum(&full)
	copy(out[:], full[8:24])
	clear(full[:])
}

func (x *MTProto) derive(messageKey *[16]byte, direction Direction) {
	var a [32]byte
	var b [32]byte
	offset := int(direction) * 8
	x.hash.reset()
	x.hash.write(messageKey[:])
	x.hash.write(x.auth[offset : offset+36])
	x.hash.sum(&a)
	x.hash.reset()
	x.hash.write(x.auth[40+offset : 76+offset])
	x.hash.write(messageKey[:])
	x.hash.sum(&b)
	copy(x.key[:8], a[:8])
	copy(x.key[8:24], b[8:24])
	copy(x.key[24:], a[24:])
	copy(x.iv[:8], b[:8])
	copy(x.iv[8:24], a[8:24])
	copy(x.iv[24:], b[24:])
	clear(a[:])
	clear(b[:])
}

func (x *MTProto) transform(dst, src []byte, decrypt bool) error {
	if len(src) == 0 {
		return nil
	}
	copy(x.engine.key[:], x.key[:])
	if nativeIGEPrepare != nil {
		nativeIGEPrepare(&x.engine.key, &x.engine.enc, &x.engine.dec)
		if decrypt {
			nativeIGEDecrypt(dst, src, &x.engine.dec, &x.iv)
		} else {
			nativeIGEEncrypt(dst, src, &x.engine.enc, &x.iv)
		}
		clear(x.engine.key[:])
		clear(x.engine.enc[:])
		clear(x.engine.dec[:])
		clear(x.key[:])
		clear(x.iv[:])
		return nil
	}
	block, err := aes.NewCipher(x.key[:])
	if err != nil {
		return err
	}
	x.engine.block = block
	err = x.engine.transform(dst, src, x.iv[:], decrypt)
	x.engine.block = nil
	clear(x.engine.key[:])
	clear(x.key[:])
	clear(x.iv[:])
	return err
}
