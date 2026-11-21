package core

import (
	"crypto/rand"
	"encoding/binary"
)

type paddingRNG struct {
	key      [32]byte
	nonce    [12]byte
	block    [64]byte
	counter  uint32
	position int
	used     uint64
	ready    bool
}

func (r *paddingRNG) bytes(dst []byte) error {
	if !r.ready || r.used+uint64(len(dst)) > 1<<20 {
		if _, err := rand.Read(r.key[:]); err != nil {
			return err
		}
		if _, err := rand.Read(r.nonce[:]); err != nil {
			clear(r.key[:])
			return err
		}
		clear(r.block[:])
		r.counter = 0
		r.position = len(r.block)
		r.used = 0
		r.ready = true
	}
	for len(dst) != 0 {
		if r.position == len(r.block) {
			r.refill()
		}
		n := copy(dst, r.block[r.position:])
		r.position += n
		r.used += uint64(n)
		dst = dst[n:]
	}
	return nil
}

func (r *paddingRNG) uint32() (uint32, error) {
	var out [4]byte
	if err := r.bytes(out[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(out[:]), nil
}

func (r *paddingRNG) refill() {
	var state [16]uint32
	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(r.key[i*4:])
	}
	state[12] = r.counter
	state[13] = binary.LittleEndian.Uint32(r.nonce[0:])
	state[14] = binary.LittleEndian.Uint32(r.nonce[4:])
	state[15] = binary.LittleEndian.Uint32(r.nonce[8:])
	work := state
	for i := 0; i < 4; i++ {
		chachaQuarter(&work[0], &work[4], &work[8], &work[12])
		chachaQuarter(&work[1], &work[5], &work[9], &work[13])
		chachaQuarter(&work[2], &work[6], &work[10], &work[14])
		chachaQuarter(&work[3], &work[7], &work[11], &work[15])
		chachaQuarter(&work[0], &work[5], &work[10], &work[15])
		chachaQuarter(&work[1], &work[6], &work[11], &work[12])
		chachaQuarter(&work[2], &work[7], &work[8], &work[13])
		chachaQuarter(&work[3], &work[4], &work[9], &work[14])
	}
	for i := range work {
		binary.LittleEndian.PutUint32(r.block[i*4:], work[i]+state[i])
	}
	r.counter++
	r.position = 0
	clear(state[:])
	clear(work[:])
}

func chachaQuarter(a, b, c, d *uint32) {
	*a += *b
	*d ^= *a
	*d = *d<<16 | *d>>16
	*c += *d
	*b ^= *c
	*b = *b<<12 | *b>>20
	*a += *b
	*d ^= *a
	*d = *d<<8 | *d>>24
	*c += *d
	*b ^= *c
	*b = *b<<7 | *b>>25
}

func (r *paddingRNG) clear() {
	clear(r.key[:])
	clear(r.nonce[:])
	clear(r.block[:])
	r.counter = 0
	r.position = 0
	r.used = 0
	r.ready = false
}
