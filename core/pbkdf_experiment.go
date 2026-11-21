package core

import (
	"crypto/sha256"
	"encoding/binary"
)

var nativeSHA256Block func(*[8]uint32, *[64]byte)
var nativePBKDF2Iterations func(*[8]uint32, *[8]uint32, *[8]uint32, *[32]byte, *[32]byte, int)

type sha256NIHMAC struct {
	inner [8]uint32
	outer [8]uint32
	state [8]uint32
	block [64]byte
}

func deriveLocalKeyNIExperiment(password, salt []byte, iterations int) ([32]byte, error) {
	var out [32]byte
	if iterations < 1 {
		return out, ErrPBKDFIterations
	}
	var engine sha256NIHMAC
	initSHA256NIHMAC(&engine, password)
	engine.first(&out, salt)
	u := out
	if nativePBKDF2Iterations != nil && iterations > 1 {
		nativePBKDF2Iterations(&engine.state, &engine.inner, &engine.outer, &u, &out, iterations-1)
	} else {
		for i := 1; i < iterations; i++ {
			engine.apply(&u)
			for j := range out {
				out[j] ^= u[j]
			}
		}
	}
	clear(u[:])
	engine.clear()
	return out, nil
}

func initSHA256NIHMAC(x *sha256NIHMAC, password []byte) {
	var key [64]byte
	if len(password) > len(key) {
		sum := sha256.Sum256(password)
		copy(key[:], sum[:])
		clear(sum[:])
	} else {
		copy(key[:], password)
	}
	for i := range x.block {
		x.block[i] = key[i] ^ 0x36
	}
	x.state = sha256InitialState()
	x.compress()
	x.inner = x.state
	for i := range x.block {
		x.block[i] = key[i] ^ 0x5c
	}
	x.state = sha256InitialState()
	x.compress()
	x.outer = x.state
	clear(key[:])
	clear(x.block[:])
	return
}

func (x *sha256NIHMAC) first(dst *[32]byte, salt []byte) {
	x.state = x.inner
	messageLength := len(salt) + 4
	offset := 0
	for offset+64 <= messageLength {
		fillPBKDFMessage(&x.block, salt, offset, 64)
		x.compress()
		offset += 64
	}
	clear(x.block[:])
	fillPBKDFMessage(&x.block, salt, offset, messageLength-offset)
	x.block[messageLength-offset] = 0x80
	if messageLength-offset >= 56 {
		x.compress()
		clear(x.block[:])
	}
	binary.BigEndian.PutUint64(x.block[56:], uint64(64+messageLength)*8)
	x.compress()
	sha256StateBytes(dst, &x.state)
	x.finishOuter(dst)
}

func fillPBKDFMessage(dst *[64]byte, salt []byte, offset, n int) {
	for i := 0; i < n; i++ {
		at := offset + i
		if at < len(salt) {
			dst[i] = salt[at]
		} else {
			dst[i] = byte(uint32(1) >> (8 * (3 - (at - len(salt)))))
		}
	}
}

func (x *sha256NIHMAC) apply(value *[32]byte) {
	x.state = x.inner
	clear(x.block[:])
	copy(x.block[:32], value[:])
	x.block[32] = 0x80
	binary.BigEndian.PutUint64(x.block[56:], 96*8)
	x.compress()
	sha256StateBytes(value, &x.state)
	x.finishOuter(value)
}

func (x *sha256NIHMAC) finishOuter(value *[32]byte) {
	x.state = x.outer
	clear(x.block[:])
	copy(x.block[:32], value[:])
	x.block[32] = 0x80
	binary.BigEndian.PutUint64(x.block[56:], 96*8)
	x.compress()
	sha256StateBytes(value, &x.state)
}

func (x *sha256NIHMAC) compress() {
	if nativeSHA256Block != nil {
		nativeSHA256Block(&x.state, &x.block)
		return
	}
	state := sha256State{h: x.state}
	state.block(x.block[:])
	x.state = state.h
}

func (x *sha256NIHMAC) clear() {
	clear(x.inner[:])
	clear(x.outer[:])
	clear(x.state[:])
	clear(x.block[:])
}

func sha256InitialState() [8]uint32 {
	return [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
}

func sha256StateBytes(dst *[32]byte, state *[8]uint32) {
	for i, word := range state {
		dst[i*4] = byte(word >> 24)
		dst[i*4+1] = byte(word >> 16)
		dst[i*4+2] = byte(word >> 8)
		dst[i*4+3] = byte(word)
	}
}
