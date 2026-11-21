package bootstrap

import (
	"encoding/binary"
	"errors"
)

const (
	constructorReqPQMulti       uint32 = 0xbe7e8ef1
	constructorResPQ            uint32 = 0x05162463
	constructorReqDHParams      uint32 = 0xd712e4be
	constructorPQInnerDataDC    uint32 = 0xa9f55f95
	constructorServerDHParamsOK uint32 = 0xd0e8075c
	constructorServerDHInner    uint32 = 0xb5890dba
	constructorSetClientDH      uint32 = 0xf5045f1f
	constructorClientDHInner    uint32 = 0x6643b654
	constructorDHGenOK          uint32 = 0x3bcbf734
	constructorDHGenRetry       uint32 = 0x46dc1fb9
	constructorDHGenFail        uint32 = 0xa69dae02
	constructorVector           uint32 = 0x1cb5c415
)

var ErrTL = errors.New("gtg: bootstrap TL data rejected")

type encoder struct {
	data []byte
}

func (x *encoder) u32(value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	x.data = append(x.data, data[:]...)
}

func (x *encoder) i32(value int32) {
	x.u32(uint32(value))
}

func (x *encoder) u64(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	x.data = append(x.data, data[:]...)
}

func (x *encoder) fixed(data []byte) {
	x.data = append(x.data, data...)
}

func (x *encoder) bytes(data []byte) {
	length := len(data)
	if length < 254 {
		x.data = append(x.data, byte(length))
	} else {
		x.data = append(x.data, 254, byte(length), byte(length>>8), byte(length>>16))
	}
	x.data = append(x.data, data...)
	for len(x.data)&3 != 0 {
		x.data = append(x.data, 0)
	}
}

type decoder struct {
	data []byte
	pos  int
}

func (x *decoder) remaining() int {
	return len(x.data) - x.pos
}

func (x *decoder) u32() (uint32, error) {
	if x.remaining() < 4 {
		return 0, ErrTL
	}
	value := binary.LittleEndian.Uint32(x.data[x.pos : x.pos+4])
	x.pos += 4
	return value, nil
}

func (x *decoder) i32() (int32, error) {
	value, err := x.u32()
	return int32(value), err
}

func (x *decoder) u64() (uint64, error) {
	if x.remaining() < 8 {
		return 0, ErrTL
	}
	value := binary.LittleEndian.Uint64(x.data[x.pos : x.pos+8])
	x.pos += 8
	return value, nil
}

func (x *decoder) fixed(length int) ([]byte, error) {
	if length < 0 || x.remaining() < length {
		return nil, ErrTL
	}
	value := x.data[x.pos : x.pos+length]
	x.pos += length
	return value, nil
}

func (x *decoder) bytes(limit int) ([]byte, error) {
	if x.remaining() < 1 || limit < 0 {
		return nil, ErrTL
	}
	first := int(x.data[x.pos])
	x.pos++
	length := first
	header := 1
	if first == 254 {
		if x.remaining() < 3 {
			return nil, ErrTL
		}
		length = int(x.data[x.pos]) | int(x.data[x.pos+1])<<8 | int(x.data[x.pos+2])<<16
		x.pos += 3
		header = 4
	} else if first == 255 {
		return nil, ErrTL
	}
	if length > limit || x.remaining() < length {
		return nil, ErrTL
	}
	value := x.data[x.pos : x.pos+length]
	x.pos += length
	padding := (4 - (length+header)&3) & 3
	if x.remaining() < padding {
		return nil, ErrTL
	}
	for _, item := range x.data[x.pos : x.pos+padding] {
		if item != 0 {
			return nil, ErrTL
		}
	}
	x.pos += padding
	return value, nil
}

type resPQ struct {
	nonce        [16]byte
	serverNonce  [16]byte
	pq           []byte
	fingerprints []uint64
}

type serverDHParams struct {
	nonce       [16]byte
	serverNonce [16]byte
	answer      []byte
}

type serverDHInner struct {
	nonce       [16]byte
	serverNonce [16]byte
	generator   int32
	prime       []byte
	public      []byte
	serverTime  int32
}

type dhGenResult struct {
	constructor uint32
	nonce       [16]byte
	serverNonce [16]byte
	newNonce    [16]byte
}

func encodeReqPQ(nonce [16]byte) []byte {
	out := encoder{data: make([]byte, 0, 20)}
	out.u32(constructorReqPQMulti)
	out.fixed(nonce[:])
	return out.data
}

func decodeResPQ(data []byte) (resPQ, error) {
	var out resPQ
	in := decoder{data: data}
	constructor, err := in.u32()
	if err != nil || constructor != constructorResPQ {
		return out, ErrTL
	}
	nonce, err := in.fixed(16)
	if err != nil {
		return out, err
	}
	copy(out.nonce[:], nonce)
	serverNonce, err := in.fixed(16)
	if err != nil {
		return out, err
	}
	copy(out.serverNonce[:], serverNonce)
	pq, err := in.bytes(8)
	if err != nil || len(pq) == 0 {
		return out, ErrTL
	}
	out.pq = append([]byte(nil), pq...)
	vector, err := in.u32()
	if err != nil || vector != constructorVector {
		return out, ErrTL
	}
	count, err := in.i32()
	if err != nil || count <= 0 || count > 64 || in.remaining() != int(count)*8 {
		return out, ErrTL
	}
	out.fingerprints = make([]uint64, count)
	for index := range out.fingerprints {
		out.fingerprints[index], err = in.u64()
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func encodePQInnerDC(pq, p, q []byte, nonce, serverNonce [16]byte, newNonce [32]byte, dcID int32) []byte {
	out := encoder{data: make([]byte, 0, 112)}
	out.u32(constructorPQInnerDataDC)
	out.bytes(pq)
	out.bytes(p)
	out.bytes(q)
	out.fixed(nonce[:])
	out.fixed(serverNonce[:])
	out.fixed(newNonce[:])
	out.i32(dcID)
	return out.data
}

func encodeReqDH(nonce, serverNonce [16]byte, p, q []byte, fingerprint uint64, encrypted []byte) []byte {
	out := encoder{data: make([]byte, 0, len(encrypted)+80)}
	out.u32(constructorReqDHParams)
	out.fixed(nonce[:])
	out.fixed(serverNonce[:])
	out.bytes(p)
	out.bytes(q)
	out.u64(fingerprint)
	out.bytes(encrypted)
	return out.data
}

func decodeServerDHParams(data []byte) (serverDHParams, error) {
	var out serverDHParams
	in := decoder{data: data}
	constructor, err := in.u32()
	if err != nil || constructor != constructorServerDHParamsOK {
		return out, ErrTL
	}
	nonce, err := in.fixed(16)
	if err != nil {
		return out, err
	}
	copy(out.nonce[:], nonce)
	serverNonce, err := in.fixed(16)
	if err != nil {
		return out, err
	}
	copy(out.serverNonce[:], serverNonce)
	answer, err := in.bytes(1 << 20)
	if err != nil || in.remaining() != 0 {
		return out, ErrTL
	}
	out.answer = append([]byte(nil), answer...)
	return out, nil
}

func decodeServerDHInner(data []byte) (serverDHInner, int, error) {
	var out serverDHInner
	in := decoder{data: data}
	constructor, err := in.u32()
	if err != nil || constructor != constructorServerDHInner {
		return out, 0, ErrTL
	}
	nonce, err := in.fixed(16)
	if err != nil {
		return out, 0, err
	}
	copy(out.nonce[:], nonce)
	serverNonce, err := in.fixed(16)
	if err != nil {
		return out, 0, err
	}
	copy(out.serverNonce[:], serverNonce)
	out.generator, err = in.i32()
	if err != nil {
		return out, 0, err
	}
	out.prime, err = in.bytes(256)
	if err != nil || len(out.prime) != 256 {
		return out, 0, ErrTL
	}
	out.public, err = in.bytes(256)
	if err != nil || len(out.public) != 256 {
		return out, 0, ErrTL
	}
	out.serverTime, err = in.i32()
	if err != nil {
		return out, 0, err
	}
	return out, in.pos, nil
}

func encodeClientDHInner(nonce, serverNonce [16]byte, retryID uint64, public []byte) []byte {
	out := encoder{data: make([]byte, 0, len(public)+64)}
	out.u32(constructorClientDHInner)
	out.fixed(nonce[:])
	out.fixed(serverNonce[:])
	out.u64(retryID)
	out.bytes(public)
	return out.data
}

func encodeSetClientDH(nonce, serverNonce [16]byte, encrypted []byte) []byte {
	out := encoder{data: make([]byte, 0, len(encrypted)+48)}
	out.u32(constructorSetClientDH)
	out.fixed(nonce[:])
	out.fixed(serverNonce[:])
	out.bytes(encrypted)
	return out.data
}

func decodeDHGen(data []byte) (dhGenResult, error) {
	var out dhGenResult
	in := decoder{data: data}
	constructor, err := in.u32()
	if err != nil || (constructor != constructorDHGenOK && constructor != constructorDHGenRetry && constructor != constructorDHGenFail) {
		return out, ErrTL
	}
	out.constructor = constructor
	nonce, err := in.fixed(16)
	if err != nil {
		return out, err
	}
	copy(out.nonce[:], nonce)
	serverNonce, err := in.fixed(16)
	if err != nil {
		return out, err
	}
	copy(out.serverNonce[:], serverNonce)
	newNonce, err := in.fixed(16)
	if err != nil || in.remaining() != 0 {
		return out, ErrTL
	}
	copy(out.newNonce[:], newNonce)
	return out, nil
}

func encodePlain(messageID uint64, body []byte) []byte {
	out := make([]byte, 20+len(body))
	binary.LittleEndian.PutUint64(out[8:16], messageID)
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(body)))
	copy(out[20:], body)
	return out
}

func decodePlain(packet []byte) (uint64, []byte, error) {
	if len(packet) < 24 || binary.LittleEndian.Uint64(packet[:8]) != 0 {
		return 0, nil, ErrTL
	}
	length := int(binary.LittleEndian.Uint32(packet[16:20]))
	if length < 4 || length&3 != 0 || length > len(packet)-20 {
		return 0, nil, ErrTL
	}
	return binary.LittleEndian.Uint64(packet[8:16]), packet[20 : 20+length], nil
}
