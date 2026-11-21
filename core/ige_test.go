package core

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
)

func TestIGEKnownAnswer(t *testing.T) {
	key := decode(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	plain := decode(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
	want := decode(t, "f3eed1bdb5d2a03c064b5a7e3db181f8880535aa181c648235a7d426c238d676")
	iv := make([]byte, 32)
	ige, err := NewIGE(key)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plain))
	if err := ige.Encrypt(got, plain, iv); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ciphertext mismatch\ngot  %x\nwant %x", got, want)
	}
	back := make([]byte, len(got))
	if err := ige.Decrypt(back, got, iv); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("plaintext mismatch\ngot  %x\nwant %x", back, plain)
	}
}

func TestIGERoundTrip(t *testing.T) {
	key := makePattern(32, 7)
	iv := makePattern(32, 23)
	ige, err := NewIGE(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 16, 32, 48, 64, 1024, 4096, 65536} {
		t.Run(stringSize(size), func(t *testing.T) {
			plain := makePattern(size, byte(size))
			ciphertext := make([]byte, size)
			if err := ige.Encrypt(ciphertext, plain, iv); err != nil {
				t.Fatal(err)
			}
			out := make([]byte, size)
			if err := ige.Decrypt(out, ciphertext, iv); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, plain) {
				t.Fatal("round-trip mismatch")
			}
			inplace := append([]byte(nil), plain...)
			if err := ige.Encrypt(inplace, inplace, iv); err != nil {
				t.Fatal(err)
			}
			if err := ige.Decrypt(inplace, inplace, iv); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(inplace, plain) {
				t.Fatal("in-place round-trip mismatch")
			}
		})
	}
}

func TestIGERejectsInvalidInputs(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 32)
	ige, err := NewIGE(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewIGE(key[:31]); !errors.Is(err, ErrIGEKeySize) {
		t.Fatalf("wrong key error: %v", err)
	}
	if err := ige.Encrypt(make([]byte, 16), make([]byte, 16), iv[:31]); !errors.Is(err, ErrIGEIVSize) {
		t.Fatalf("wrong IV error: %v", err)
	}
	if err := ige.Encrypt(make([]byte, 15), make([]byte, 15), iv); !errors.Is(err, ErrIGEBlockSize) {
		t.Fatalf("wrong block error: %v", err)
	}
	if err := ige.Encrypt(make([]byte, 16), make([]byte, 32), iv); !errors.Is(err, ErrIGEDestination) {
		t.Fatalf("wrong destination error: %v", err)
	}
	buf := make([]byte, 33)
	if err := ige.Encrypt(buf[1:17], buf[:16], iv); !errors.Is(err, ErrIGEOverlap) {
		t.Fatalf("wrong overlap error: %v", err)
	}
}

func TestIGEAllocs(t *testing.T) {
	key := makePattern(32, 1)
	iv := makePattern(32, 2)
	ige, err := NewIGE(key)
	if err != nil {
		t.Fatal(err)
	}
	src := makePattern(65536, 3)
	dst := make([]byte, len(src))
	for _, decrypt := range []bool{false, true} {
		input := src
		if decrypt {
			input = make([]byte, len(src))
			if err := ige.Encrypt(input, src, iv); err != nil {
				t.Fatal(err)
			}
		}
		allocs := testing.AllocsPerRun(1000, func() {
			var err error
			if decrypt {
				err = ige.Decrypt(dst, input, iv)
			} else {
				err = ige.Encrypt(dst, input, iv)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
		if allocs != 0 {
			t.Fatalf("decrypt=%v allocs/op = %v, want 0", decrypt, allocs)
		}
	}
}

func makePattern(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i*31) + seed
	}
	return out
}

func stringSize(size int) string {
	return strconv.Itoa(size)
}

func decode(t *testing.T, text string) []byte {
	t.Helper()
	out := make([]byte, len(text)/2)
	for i := range out {
		var high, low byte
		high = fromHex(t, text[i*2])
		low = fromHex(t, text[i*2+1])
		out[i] = high<<4 | low
	}
	return out
}

func fromHex(t *testing.T, b byte) byte {
	t.Helper()
	switch {
	case '0' <= b && b <= '9':
		return b - '0'
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10
	case 'A' <= b && b <= 'F':
		return b - 'A' + 10
	default:
		t.Fatalf("invalid hex digit %q", b)
		return 0
	}
}

func TestIGEEncryptBatch(t *testing.T) {
	key := makePattern(32, 8)
	ige, err := NewIGE(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{16, 32, 64, 4096} {
		streams := make([]IGEStream, 4)
		wants := make([][]byte, 4)
		for i := range streams {
			plain := makePattern(size, byte(i+31))
			iv := makePattern(32, byte(i+61))
			wants[i] = make([]byte, size)
			if err := ige.Encrypt(wants[i], plain, iv); err != nil {
				t.Fatal(err)
			}
			streams[i] = IGEStream{Dst: append([]byte(nil), plain...), Src: nil, IV: iv}
			streams[i].Src = streams[i].Dst
		}
		if err := ige.EncryptBatch(streams); err != nil {
			t.Fatal(err)
		}
		for i := range streams {
			if !bytes.Equal(streams[i].Dst, wants[i]) {
				t.Fatalf("batch mismatch size=%d stream=%d", size, i)
			}
		}
	}
}

func TestIGEVariedKeyBatch(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		for _, count := range []int{1, 3, 4, 6, 8} {
			streams := make([]IGEKeyStream, count)
			wants := make([][]byte, count)
			for i := range streams {
				size := 16 * (i%4 + 1)
				if i >= 4 {
					size = 4096
				}
				key := makePattern(32, byte(20+i))
				iv := makePattern(32, byte(40+i))
				plain := makePattern(size, byte(60+i))
				ige, err := NewIGE(key)
				if err != nil {
					t.Fatal(err)
				}
				src := plain
				if decrypt {
					src = make([]byte, size)
					if err := ige.Encrypt(src, plain, iv); err != nil {
						t.Fatal(err)
					}
					wants[i] = plain
				} else {
					wants[i] = make([]byte, size)
					if err := ige.Encrypt(wants[i], plain, iv); err != nil {
						t.Fatal(err)
					}
				}
				streams[i] = IGEKeyStream{IGE: ige, Dst: append([]byte(nil), src...), Src: nil, IV: iv}
				streams[i].Src = streams[i].Dst
			}
			var err error
			if decrypt {
				err = DecryptBatchVaried(streams)
			} else {
				err = EncryptBatchVaried(streams)
			}
			if err != nil {
				t.Fatal(err)
			}
			for i := range streams {
				if !bytes.Equal(streams[i].Dst, wants[i]) {
					t.Fatalf("decrypt=%v count=%d stream=%d mismatch", decrypt, count, i)
				}
			}
		}
	}
}

func TestIGEVariedKeyBatchAllocs(t *testing.T) {
	streams := make([]IGEKeyStream, 4)
	for i := range streams {
		ige, err := NewIGE(makePattern(32, byte(i+1)))
		if err != nil {
			t.Fatal(err)
		}
		streams[i] = IGEKeyStream{IGE: ige, Src: makePattern(65536, byte(i+10)), Dst: make([]byte, 65536), IV: makePattern(32, byte(i+20))}
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := EncryptBatchVaried(streams); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("allocs/op = %v, want 0", allocs)
	}
}

func TestIGEVariedKeyBatchNativeGroups(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		streams := make([]IGEKeyStream, 8)
		wants := make([][]byte, len(streams))
		for i := range streams {
			key := makePattern(32, byte(i+3))
			iv := makePattern(32, byte(i+17))
			plain := makePattern(4096, byte(i+31))
			ige, err := NewIGE(key)
			if err != nil {
				t.Fatal(err)
			}
			src := plain
			if decrypt {
				src = make([]byte, len(plain))
				if err := ige.Encrypt(src, plain, iv); err != nil {
					t.Fatal(err)
				}
				wants[i] = plain
			} else {
				wants[i] = make([]byte, len(plain))
				if err := ige.Encrypt(wants[i], plain, iv); err != nil {
					t.Fatal(err)
				}
			}
			streams[i] = IGEKeyStream{IGE: ige, Dst: append([]byte(nil), src...), Src: nil, IV: iv}
			streams[i].Src = streams[i].Dst
		}
		var err error
		if decrypt {
			err = DecryptBatchVaried(streams)
		} else {
			err = EncryptBatchVaried(streams)
		}
		if err != nil {
			t.Fatal(err)
		}
		for i := range streams {
			if !bytes.Equal(streams[i].Dst, wants[i]) {
				t.Fatalf("native decrypt=%v stream=%d mismatch", decrypt, i)
			}
		}
	}
}

func TestIGEPool(t *testing.T) {
	pool, err := NewIGEPool(4)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, decrypt := range []bool{false, true} {
		streams := make([]IGEKeyStream, 8)
		wants := make([][]byte, len(streams))
		for i := range streams {
			ige, err := NewIGE(makePattern(32, byte(i+11)))
			if err != nil {
				t.Fatal(err)
			}
			iv := makePattern(32, byte(i+31))
			plain := makePattern(4096, byte(i+51))
			src := plain
			if decrypt {
				src = make([]byte, len(plain))
				if err := ige.Encrypt(src, plain, iv); err != nil {
					t.Fatal(err)
				}
				wants[i] = plain
			} else {
				wants[i] = make([]byte, len(plain))
				if err := ige.Encrypt(wants[i], plain, iv); err != nil {
					t.Fatal(err)
				}
			}
			streams[i] = IGEKeyStream{IGE: ige, Dst: make([]byte, len(src)), Src: src, IV: iv}
		}
		if decrypt {
			err = pool.Decrypt(streams)
		} else {
			err = pool.Encrypt(streams)
		}
		if err != nil {
			t.Fatal(err)
		}
		for i := range streams {
			if !bytes.Equal(streams[i].Dst, wants[i]) {
				t.Fatalf("decrypt=%v stream=%d", decrypt, i)
			}
		}
	}
}

func TestIGEPoolAllocs(t *testing.T) {
	pool, err := NewIGEPool(4)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	streams := make([]IGEKeyStream, 4)
	for i := range streams {
		ige, err := NewIGE(makePattern(32, byte(i+1)))
		if err != nil {
			t.Fatal(err)
		}
		streams[i] = IGEKeyStream{IGE: ige, Dst: make([]byte, 65536), Src: makePattern(65536, byte(i+10)), IV: makePattern(32, byte(i+20))}
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := pool.Encrypt(streams); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("allocs/op=%v, want 0", allocs)
	}
}

func TestAES256Schedule(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	var input [32]byte
	var enc [240]byte
	var dec [240]byte
	copy(input[:], key)
	expand256Schedule(&input, &enc, &dec)
	want := decode(t, "24fc79ccbf0979e9371ac23c6d68de36")
	if !bytes.Equal(enc[224:], want) {
		t.Fatalf("last round key got=%x want=%x", enc[224:], want)
	}
	if !bytes.Equal(dec[:16], enc[224:]) || !bytes.Equal(dec[224:], enc[:16]) {
		t.Fatal("reverse schedule mismatch")
	}
}
