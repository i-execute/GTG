package core

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"unsafe"
)

var ErrIGEKeySize = errors.New("gtg: AES-IGE key must be 32 bytes")
var ErrIGEIVSize = errors.New("gtg: AES-IGE IV must be 32 bytes")
var ErrIGEBlockSize = errors.New("gtg: AES-IGE input must be a multiple of 16 bytes")
var ErrIGEDestination = errors.New("gtg: AES-IGE destination is too short")
var ErrIGEOverlap = errors.New("gtg: AES-IGE invalid buffer overlap")

type IGE struct {
	block cipher.Block
	key   [32]byte
	enc   [240]byte
	dec   [240]byte
}

var nativeIGEPrepare func(*[32]byte, *[240]byte, *[240]byte)
var nativeIGEEncrypt func([]byte, []byte, *[240]byte, *[32]byte)
var nativeIGEDecrypt func([]byte, []byte, *[240]byte, *[32]byte)
var nativeIGEEncrypt4 func(*IGEStream, *[240]byte, uintptr)
var nativeIGEReferenceEncrypt func([]byte, []byte, *[240]byte)
var nativeIGEReferenceDecrypt func([]byte, []byte, *[240]byte)
var nativeIGEEncrypt4Varied func(*IGEKeyStream, uintptr)
var nativeIGEDecrypt4Varied func(*IGEKeyStream, uintptr)

func NewIGE(key []byte) (*IGE, error) {
	if len(key) != 32 {
		return nil, ErrIGEKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	x := &IGE{block: block}
	copy(x.key[:], key)
	if nativeIGEPrepare != nil {
		nativeIGEPrepare(&x.key, &x.enc, &x.dec)
	}
	return x, nil
}

func (x *IGE) Destroy() {
	clear(x.key[:])
	clear(x.enc[:])
	clear(x.dec[:])
	x.block = nil
}

func (x *IGE) Encrypt(dst, src, iv []byte) error {
	return x.transform(dst, src, iv, false)
}

func (x *IGE) Decrypt(dst, src, iv []byte) error {
	return x.transform(dst, src, iv, true)
}

func (x *IGE) transform(dst, src, iv []byte, decrypt bool) error {
	if len(iv) != 32 {
		return ErrIGEIVSize
	}
	if len(src)&15 != 0 {
		return ErrIGEBlockSize
	}
	if len(dst) < len(src) {
		return ErrIGEDestination
	}
	if invalidOverlap(dst[:len(src)], src) {
		return ErrIGEOverlap
	}
	if len(src) == 0 {
		return nil
	}
	nativeIV := (*[32]byte)(unsafe.Pointer(unsafe.SliceData(iv)))
	if decrypt && nativeIGEDecrypt != nil {
		nativeIGEDecrypt(dst[:len(src)], src, &x.dec, nativeIV)
		return nil
	}
	if !decrypt && nativeIGEEncrypt != nil {
		nativeIGEEncrypt(dst[:len(src)], src, &x.enc, nativeIV)
		return nil
	}
	var c [16]byte
	var p [16]byte
	copy(c[:], iv[:16])
	copy(p[:], iv[16:])
	for len(src) != 0 {
		input := *(*[16]byte)(unsafe.Pointer(unsafe.SliceData(src)))
		output := (*[16]byte)(unsafe.Pointer(unsafe.SliceData(dst)))
		if decrypt {
			xorBlock(output, &input, &p)
			x.block.Decrypt(output[:], output[:])
			xorBlock(output, output, &c)
			c = input
			p = *output
		} else {
			xorBlock(output, &input, &c)
			x.block.Encrypt(output[:], output[:])
			xorBlock(output, output, &p)
			c = *output
			p = input
		}
		src = src[16:]
		dst = dst[16:]
	}
	clear(c[:])
	clear(p[:])
	return nil
}

func xorBlock(dst, a, b *[16]byte) {
	d0 := *(*uint64)(unsafe.Pointer(&a[0])) ^ *(*uint64)(unsafe.Pointer(&b[0]))
	d1 := *(*uint64)(unsafe.Pointer(&a[8])) ^ *(*uint64)(unsafe.Pointer(&b[8]))
	*(*uint64)(unsafe.Pointer(&dst[0])) = d0
	*(*uint64)(unsafe.Pointer(&dst[8])) = d1
}

func invalidOverlap(dst, src []byte) bool {
	if len(dst) == 0 || len(src) == 0 {
		return false
	}
	d := uintptr(unsafe.Pointer(unsafe.SliceData(dst)))
	s := uintptr(unsafe.Pointer(unsafe.SliceData(src)))
	if d == s {
		return false
	}
	return d < s+uintptr(len(src)) && s < d+uintptr(len(dst))
}

type IGEStream struct {
	Dst []byte
	Src []byte
	IV  []byte
}

func (x *IGE) EncryptBatch(streams []IGEStream) error {
	if len(streams) == 0 {
		return nil
	}
	blocks := -1
	for i := range streams {
		stream := &streams[i]
		if len(stream.IV) != 32 {
			return ErrIGEIVSize
		}
		if len(stream.Src)&15 != 0 {
			return ErrIGEBlockSize
		}
		if len(stream.Dst) < len(stream.Src) {
			return ErrIGEDestination
		}
		if invalidOverlap(stream.Dst[:len(stream.Src)], stream.Src) {
			return ErrIGEOverlap
		}
		if blocks < 0 {
			blocks = len(stream.Src) >> 4
		} else if blocks != len(stream.Src)>>4 {
			return ErrIGEBlockSize
		}
	}
	for len(streams) >= 4 && blocks != 0 && nativeIGEEncrypt4 != nil {
		nativeIGEEncrypt4(&streams[0], &x.enc, uintptr(blocks))
		streams = streams[4:]
	}
	for i := range streams {
		if err := x.Encrypt(streams[i].Dst, streams[i].Src, streams[i].IV); err != nil {
			return err
		}
	}
	return nil
}

type IGEKeyStream struct {
	IGE *IGE
	Dst []byte
	Src []byte
	IV  []byte
}

func EncryptBatchVaried(streams []IGEKeyStream) error {
	return transformBatchVaried(streams, false)
}

func DecryptBatchVaried(streams []IGEKeyStream) error {
	return transformBatchVaried(streams, true)
}

func transformBatchVaried(streams []IGEKeyStream, decrypt bool) error {
	if err := validateIGEKeyStreams(streams); err != nil {
		return err
	}
	for len(streams) != 0 {
		if len(streams) >= 4 && len(streams[0].Src) != 0 && equalStreamBlockCounts(streams[:4]) {
			blocks := uintptr(len(streams[0].Src) >> 4)
			if decrypt && nativeIGEDecrypt4Varied != nil {
				nativeIGEDecrypt4Varied(&streams[0], blocks)
				streams = streams[4:]
				continue
			}
			if !decrypt && nativeIGEEncrypt4Varied != nil {
				nativeIGEEncrypt4Varied(&streams[0], blocks)
				streams = streams[4:]
				continue
			}
		}
		stream := &streams[0]
		var err error
		if decrypt {
			err = stream.IGE.Decrypt(stream.Dst, stream.Src, stream.IV)
		} else {
			err = stream.IGE.Encrypt(stream.Dst, stream.Src, stream.IV)
		}
		if err != nil {
			return err
		}
		streams = streams[1:]
	}
	return nil
}

func equalStreamBlockCounts(streams []IGEKeyStream) bool {
	blocks := len(streams[0].Src)
	for i := 1; i < len(streams); i++ {
		if len(streams[i].Src) != blocks {
			return false
		}
	}
	return true
}

func validateIGEKeyStreams(streams []IGEKeyStream) error {
	for i := range streams {
		stream := &streams[i]
		if stream.IGE == nil {
			return ErrIGEKeySize
		}
		if len(stream.IV) != 32 {
			return ErrIGEIVSize
		}
		if len(stream.Src)&15 != 0 {
			return ErrIGEBlockSize
		}
		if len(stream.Dst) < len(stream.Src) {
			return ErrIGEDestination
		}
		if invalidOverlap(stream.Dst[:len(stream.Src)], stream.Src) {
			return ErrIGEOverlap
		}
	}
	return nil
}
